package me.bluegecko.wristhello.presentation

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import androidx.core.graphics.createBitmap
import androidx.core.graphics.set

fun generateQrCode(
    content: String,
    size: Int = 300,
    foregroundColor: Int = Color.BLACK,
    backgroundColor: Int = Color.WHITE
): Bitmap {
    val hints = mapOf(
        EncodeHintType.CHARACTER_SET to "UTF-8",
        EncodeHintType.MARGIN to 1
    )

    val writer = QRCodeWriter()
    val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size, hints)

    val bitmap = createBitmap(size, size)
    for (x in 0 until size) {
        for (y in 0 until size) {
            bitmap[x, y] = if (bitMatrix[x, y]) foregroundColor else backgroundColor
        }
    }
    return bitmap
}
