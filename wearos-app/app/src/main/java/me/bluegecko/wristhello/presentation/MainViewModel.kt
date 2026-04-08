package me.bluegecko.wristhello.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val keyStoreManager = KeystoreManager()
    private val bleManager = BleManager(app, keyStoreManager)

    val bleState: StateFlow<BleState> = bleManager.bleState.stateIn(
        viewModelScope, SharingStarted.Lazily,
        BleState.Disconnected
    )

    @androidx.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)
    fun connect() {
        viewModelScope.launch  {
            bleManager.connectToPairedDevice()
        }
    }

    @androidx.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)
    fun disconnect() {
        bleManager.disconnect()
    }
}
