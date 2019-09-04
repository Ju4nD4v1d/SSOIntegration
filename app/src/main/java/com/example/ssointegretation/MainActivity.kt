package com.example.ssointegretation

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.annotation.MainThread
import androidx.annotation.WorkerThread
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import io.reactivex.Observer
import io.reactivex.disposables.Disposable
import kotlinx.android.synthetic.main.activity_main.*
import net.openid.appauth.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

class MainActivity : AppCompatActivity() {

    companion object {
        private const val EXTRA_FAILED = "failed"
        private const val RC_AUTH = 100
        private const val DEV_TAG = "safefleetdev"
        private const val TEST_TAG = "safefleettest"
    }

    private lateinit var mAuthStateManager: AuthStateManager
    private var mAuthService: AuthorizationService? = null
    private lateinit var mConfiguration: Configuration

    private val mClientId = AtomicReference<String>()
    private val mAuthRequest = AtomicReference<AuthorizationRequest>()
    private val mAuthIntent = AtomicReference<CustomTabsIntent>()
    private var mExecutor: ExecutorService? = null

    private var chosenProvider: String = ""

    private var authServerObserver = object : Observer<Boolean> {
        override fun onComplete() {
        }

        override fun onSubscribe(d: Disposable) {
        }

        override fun onNext(t: Boolean) {
            if (t) {
                startAuth()
            }
        }

        override fun onError(e: Throwable) {
        }

    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        mExecutor = Executors.newSingleThreadExecutor()
        mAuthStateManager = AuthStateManager.getInstance(this)
        if (intent.getBooleanExtra(EXTRA_FAILED, false)) {
            displayAuthCancelled()
        }

        button_authenticate.setOnClickListener {
            chosenProvider = TEST_TAG
            recreateAuthorizationService()
        }

        button_logout.setOnClickListener {
            mAuthStateManager.resetState()
        }
    }

    private fun displayAuthCancelled() {
        Toast.makeText(this, "Authorization canceled", Toast.LENGTH_SHORT).show()
    }

    private fun recreateAuthorizationService() {
        if (mAuthService != null) {
            mAuthService!!.dispose()
        }
        mAuthService = AuthorizationService(this)
        mAuthRequest.set(null)
        mAuthIntent.set(null)

        startAuthProcess()
    }

    private fun startAuthProcess() {
        mConfiguration = Configuration.getInstance(this, chosenProvider)
        if (!mConfiguration.isValid) {
            return
        }
        mConfiguration.acceptConfiguration()
        mExecutor?.submit {
            initializeAppAuth()
        }
    }

    @WorkerThread
    private fun initializeAppAuth() {
        val config = AuthorizationServiceConfiguration(
            mConfiguration.authEndpointUri!!,
            mConfiguration.tokenEndpointUri!!
        )
        mAuthStateManager.replace(AuthState(config))
        initializeClient()
        return
    }

    @WorkerThread
    private fun initializeClient() {
        mClientId.set(mConfiguration.clientId)
        runOnUiThread { createAuthRequest() }
        return
    }

    private fun createAuthRequest() {
        val authRequestBuilder = AuthorizationRequest.Builder(
            mAuthStateManager.current.authorizationServiceConfiguration!!,
            mClientId.get(),
            ResponseTypeValues.CODE,
            mConfiguration.redirectUri!!
        ).setScope(mConfiguration.scope!!)
        mAuthRequest.set(authRequestBuilder.build())
        authServerObserver.onNext(true)
    }

    @MainThread
    private fun startAuth() {
        mExecutor?.submit { doAuth() }
    }

    @WorkerThread
    private fun doAuth() {
        val intent =
            mAuthService?.getAuthorizationRequestIntent(mAuthRequest.get())
        startActivityForResult(intent, RC_AUTH)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_CANCELED) {
            displayAuthCancelled()
        } else {
            val response = AuthorizationResponse.fromIntent(data!!)
            val ex = AuthorizationException.fromIntent(data)
            when {
                response?.authorizationCode != null -> {
                    mAuthStateManager.updateAfterAuthorization(response, ex)
                    exchangeAuthorizationCode(response)
                }
                ex != null -> return // Authorization flow failed
                else -> return // No authorization state retained - reauthorization required
            }
        }
    }


    private fun exchangeAuthorizationCode(authorizationResponse: AuthorizationResponse) {
        performTokenRequest(
            authorizationResponse.createTokenExchangeRequest(),
            AuthorizationService.TokenResponseCallback { tokenResponse, authException ->
                this.handleCodeExchangeResponse(
                    tokenResponse,
                    authException
                )
            })
    }

    private fun performTokenRequest(
        request: TokenRequest,
        callback: AuthorizationService.TokenResponseCallback
    ) {
        val clientAuthentication: ClientAuthentication
        try {
            clientAuthentication = mAuthStateManager.current.clientAuthentication
        } catch (ex: ClientAuthentication.UnsupportedAuthenticationMethod) {
            // Token request cannot be made, client authentication for the token endpoint could not be constructed
            return
        }
        val finalRequest: TokenRequest = getFinalRequest(request)

        mAuthService!!.performTokenRequest(finalRequest, clientAuthentication, callback)
    }

    private fun getFinalRequest(request: TokenRequest): TokenRequest {
        val params = HashMap<String, String>()
        when (chosenProvider) {
            DEV_TAG -> params["client_secret"] = "e44db0d7-841b-bd5c-bbfb-ff6d6dc0d448"
            TEST_TAG -> params["client_secret"] = ""
        }

        return TokenRequest.Builder(request.configuration, request.clientId)
            .setGrantType(request.grantType)
            .setAuthorizationCode(request.authorizationCode)
            .setRedirectUri(request.redirectUri)
            .setCodeVerifier(request.codeVerifier)
            .setScope(request.scope)
            .setRefreshToken(request.refreshToken)
            .setAdditionalParameters(params)
            .build()
    }

    private fun handleCodeExchangeResponse(
        tokenResponse: TokenResponse?,
        authException: AuthorizationException?
    ) {
        if (authException != null) {
            // Log the error
            return
        }
        mAuthStateManager.updateAfterTokenResponse(tokenResponse, authException)
        textView.text = tokenResponse!!.accessToken!!
    }
}
