package me.bluegecko.wristhello.presentation

import android.app.Application
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.StateFlow

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val keyStoreManager = KeystoreManager()
    val bleState: StateFlow<BleState> = BleServiceState.bleState

    fun reconnect() {
        val context = getApplication<Application>()
        ContextCompat.startForegroundService(
            context,
            Intent(
                context,
                ForegroundService::class.java
            ).setAction(ForegroundService.ACTION_RECONNECT)
        )
    }

    fun getPublicKey(): ByteArray {
        return keyStoreManager.getOrGenerateRawPublicKey()
    }
}
