package com.example.pubgwireguardtester

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.*
import android.graphics.Color
import android.view.ViewGroup
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.util.concurrent.Executors
import kotlin.math.abs

class MainActivity : Activity() {

    private val executor = Executors.newSingleThreadExecutor()
    private val PICK_FILES = 101
    private val VPN_PERMISSION = 102

    private lateinit var backend: GoBackend
    private lateinit var status: TextView
    private lateinit var filesText: TextView
    private lateinit var ips: EditText
    private lateinit var output: TextView

    private val configs = mutableListOf<Pair<String, ByteArray>>()
    private var pendingConfig: Config? = null
    private var connected = false

    private val tunnel = object : Tunnel {
        override fun getName() = "PUBGTester"

        override fun onStateChange(newState: Tunnel.State) {
            runOnUiThread {
                status.text = "حالة الاتصال: $newState"
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        backend = GoBackend(applicationContext)
        buildInterface()
    }

    private fun buildInterface() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(22, 25, 22, 25)
            setBackgroundColor(Color.rgb(13, 18, 29))
        }

        fun label(value: String, size: Float = 16f): TextView {
            return TextView(this).apply {
                text = value
                textSize = size
                setTextColor(Color.WHITE)
                setPadding(0, 10, 0, 10)
            }
        }

        fun addButton(title: String, action: () -> Unit) {
            val button = Button(this).apply {
                text = title
                setOnClickListener { action() }
            }
            root.addView(button)
        }

        root.addView(label("PUBG WIREGUARD TESTER", 23f))
        root.addView(label("اختبار اتصالات PUBG Mobile", 15f))

        status = label("حالة الاتصال: غير متصل")
        root.addView(status)

        addButton("استيراد ملفات WireGuard") {
            chooseFiles()
        }

        filesText = label("لم تتم إضافة ملفات بعد")
        root.addView(filesText)

        root.addView(label("عناوين IP المستهدفة:"))

        ips = EditText(this).apply {
            hint = "عنوان IP في كل سطر"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setBackgroundColor(Color.rgb(30, 39, 55))
            minLines = 3
            setPadding(12, 10, 12, 10)
        }

        root.addView(
            ips,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        )

        addButton("تشغيل أول ملف WireGuard") {
            connectFirst()
        }

        addButton("اختبار Ping") {
            testPing()
        }

        addButton("اختبار سرعة الإنترنت") {
            testSpeed()
        }

        addButton("إيقاف الاتصال") {
            disconnect()
        }

        root.addView(label("نتائج الاختبار:", 18f))

        output = label("ستظهر النتائج هنا.")
        root.addView(output)

        root.addView(
            label(
                "ملاحظة: بعض سيرفرات PUBG لا تستجيب لطلبات Ping.",
                12f
            )
        )

        setContentView(
            ScrollView(this).apply {
                addView(root)
            }
        )
    }

    private fun chooseFiles() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }

        startActivityForResult(intent, PICK_FILES)
    }

    @Deprecated("Required for compatibility")
    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == VPN_PERMISSION) {
            if (resultCode == RESULT_OK) {
                activateVPN()
            } else {
                output.text = "لم يتم منح إذن VPN."
            }
            return
        }

        if (requestCode == PICK_FILES &&
            resultCode == RESULT_OK &&
            data != null
        ) {
            val selected = mutableListOf<android.net.Uri>()

            data.clipData?.let {
                for (i in 0 until it.itemCount) {
                    selected.add(it.getItemAt(i).uri)
                }
            } ?: data.data?.let {
                selected.add(it)
            }

            for (uri in selected) {
                try {
                    val bytes = contentResolver
                        .openInputStream(uri)?.use { it.readBytes() }
                        ?: continue

                    val config = Config.parse(
                        ByteArrayInputStream(bytes)
                    )

                    val name = uri.lastPathSegment
                        ?: "WireGuard.conf"

                    configs.add(name to bytes)

                } catch (e: Exception) {
                    Toast.makeText(
                        this,
                        "ملف غير صالح: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }

            filesText.text = configs.mapIndexed { index, item ->
                "${index + 1}. ${item.first}"
            }.joinToString("\n")
        }
    }

    private fun connectFirst() {
        if (configs.isEmpty()) {
            output.text = "استورد ملف WireGuard أولاً."
            return
        }

        try {
            pendingConfig = Config.parse(
                ByteArrayInputStream(configs.first().second)
            )

            val permission = VpnService.prepare(this)

            if (permission != null) {
                startActivityForResult(
                    permission,
                    VPN_PERMISSION
                )
            } else {
                activateVPN()
            }

        } catch (e: Exception) {
            output.text = "خطأ: ${e.message}"
        }
    }

    private fun activateVPN() {
        val config = pendingConfig ?: return

        executor.execute {
            try {
                backend.setState(
                    tunnel,
                    Tunnel.State.UP,
                    config
                )

                connected = true

                runOnUiThread {
                    status.text = "حالة الاتصال: متصل"
                    output.text = "تم تشغيل نفق WireGuard."
                }

            } catch (e: Exception) {
                runOnUiThread {
                    output.text = "فشل الاتصال: ${e.message}"
                }
            }
        }
    }

    private fun testPing() {
        val hosts = ips.text.toString()
            .lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()

        if (!connected) {
            output.text = "شغّل اتصال WireGuard أولاً."
            return
        }

        if (hosts.isEmpty()) {
            output.text = "أدخل عناوين IP أولاً."
            return
        }

        output.text = "جارٍ اختبار Ping..."

        executor.execute {
            val results = mutableListOf<String>()

            for (host in hosts) {
                try {
                    if (!host.matches(
                        Regex("[0-9a-fA-F:.%]+")
                    )) {
                        results.add("$host : عنوان غير صالح")
                        continue
                    }

                    val process = ProcessBuilder(
                        "ping", "-c", "5", "-W", "2", host
                    ).redirectErrorStream(true).start()

                    val response = process.inputStream
                        .bufferedReader().readText()

                    process.waitFor()

                    val times = Regex(
                        "time[=<]([0-9.]+)"
                    ).findAll(response)
                        .mapNotNull {
                            it.groupValues[1].toDoubleOrNull()
                        }.toList()

                    val loss = Regex(
                        "(\\d+(?:\\.\\d+)?)% packet loss"
                    ).find(response)?.groupValues?.get(1)

                    if (times.isNotEmpty()) {
                        val average = times.average()

                        val jitter = if (times.size > 1) {
                            times.zipWithNext { a, b ->
                                abs(a - b)
                            }.average()
                        } else 0.0

                        results.add(
                            "$host\n" +
                            "Ping: %.1f ms\n".format(average) +
                            "Jitter: %.1f ms\n".format(jitter) +
                            "Loss: ${loss ?: "غير معروف"}%"
                        )

                    } else {
                        results.add(
                            "$host: لا توجد استجابة ICMP"
                        )
                    }

                } catch (e: Exception) {
                    results.add("$host: ${e.message}")
                }
            }

            runOnUiThread {
                output.text = results.joinToString("\n\n")
            }
        }
    }

    private fun testSpeed() {
        if (!connected) {
            output.text = "شغّل WireGuard أولاً."
            return
        }

        output.text = "جارٍ اختبار سرعة التحميل..."

        executor.execute {
            try {
                val bytes = 5_000_000L
                val start = System.nanoTime()

                val connection = URL(
                    "https://speed.cloudflare.com/__down?bytes=$bytes"
                ).openConnection() as HttpsURLConnection

                connection.connectTimeout = 15000
                connection.readTimeout = 30000

                val total = connection.inputStream.use { stream ->
                    val buffer = ByteArray(65536)
                    var count = 0L

                    while (true) {
                        val n = stream.read(buffer)
                        if (n < 0) break
                        count += n
                    }

                    count
                }

                connection.disconnect()

                val seconds =
                    (System.nanoTime() - start) / 1e9

                val speed =
                    total * 8 / seconds / 1_000_000

                runOnUiThread {
                    output.text =
                        "Download: %.2f Mbps".format(speed) +
                        "\n\nتم القياس عبر HTTPS."
                }

            } catch (e: Exception) {
                runOnUiThread {
                    output.text = "فشل الاختبار: ${e.message}"
                }
            }
        }
    }

    private fun disconnect() {
        executor.execute {
            try {
                backend.setState(
                    tunnel,
                    Tunnel.State.DOWN,
                    null
                )

                connected = false

                runOnUiThread {
                    status.text = "حالة الاتصال: غير متصل"
                    output.text = "تم إيقاف الاتصال."
                }

            } catch (e: Exception) {
                runOnUiThread {
                    output.text = "خطأ: ${e.message}"
                }
            }
        }
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
