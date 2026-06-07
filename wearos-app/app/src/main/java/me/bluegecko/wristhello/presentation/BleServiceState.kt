package me.bluegecko.wristhello.presentation

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object BleServiceState {
    private val _bleState = MutableStateFlow<BleState>(BleState.Disconnected)
    val bleState: StateFlow<BleState> = _bleState

    fun update(state: BleState) {
        _bleState.value = state
    }
}
