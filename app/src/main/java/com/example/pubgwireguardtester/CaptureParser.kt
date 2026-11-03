package com.example.pubgwireguardtester

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Extracts public IP endpoints from classic PCAP and PCAPNG files.
 * Supports Ethernet (including VLAN), raw IP and Linux cooked captures.
 */
object CaptureParser {
    fun extract(data: ByteArray): Set<String> {
        if (data.size < 4) return emptySet()
        return when {
            isClassicPcap(data) -> parseClassicPcap(data)
            isPcapNg(data) -> parsePcapNg(data)
            else -> throw IllegalArgumentException("صيغة الملف ليست PCAP أو PCAPNG")
        }
    }

    private fun isClassicPcap(b: ByteArray) =
        b.size >= 24 && (
            (b[0] == 0xd4.toByte() && b[1] == 0xc3.toByte() && b[2] == 0xb2.toByte() && b[3] == 0xa1.toByte()) ||
            (b[0] == 0xa1.toByte() && b[1] == 0xb2.toByte() && b[2] == 0xc3.toByte() && b[3] == 0xd4.toByte()) ||
            (b[0] == 0x4d.toByte() && b[1] == 0x3c.toByte() && b[2] == 0xb2.toByte() && b[3] == 0xa1.toByte()) ||
            (b[0] == 0xa1.toByte() && b[1] == 0xb2.toByte() && b[2] == 0x3c.toByte() && b[3] == 0x4d.toByte())
        )

    private fun isPcapNg(b: ByteArray) =
        b.size >= 12 && b[0] == 0x0a.toByte() && b[1] == 0x0d.toByte() &&
            b[2] == 0x0d.toByte() && b[3] == 0x0a.toByte()

    private fun parseClassicPcap(data: ByteArray): Set<String> {
        val little = data[0] == 0xd4.toByte() || data[0] == 0x4d.toByte()
        val order = if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val linkType = u32(data, 20, order)
        val found = linkedSetOf<String>()
        var offset = 24
        while (offset + 16 <= data.size) {
            val captured = u32(data, offset + 8, order)
            if (captured < 0 || captured > data.size - offset - 16) break
            parsePacket(data, offset + 16, captured, linkType, found)
            offset += 16 + captured
        }
        return found
    }

    private fun parsePcapNg(data: ByteArray): Set<String> {
        val found = linkedSetOf<String>()
        val interfaces = mutableListOf<Long>()
        var order = ByteOrder.LITTLE_ENDIAN
        var offset = 0
        while (offset + 12 <= data.size) {
            if (data[offset] == 0x0a.toByte() && data[offset + 1] == 0x0d.toByte() &&
                data[offset + 2] == 0x0d.toByte() && data[offset + 3] == 0x0a.toByte()) {
                if (offset + 12 > data.size) break
                order = when {
                    data[offset + 8] == 0x4d.toByte() && data[offset + 9] == 0x3c.toByte() &&
                        data[offset + 10] == 0x2b.toByte() && data[offset + 11] == 0x1a.toByte() -> ByteOrder.LITTLE_ENDIAN
                    data[offset + 8] == 0x1a.toByte() && data[offset + 9] == 0x2b.toByte() &&
                        data[offset + 10] == 0x3c.toByte() && data[offset + 11] == 0x4d.toByte() -> ByteOrder.BIG_ENDIAN
                    else -> break
                }
                interfaces.clear()
            }
            val type = u32(data, offset, order)
            val blockLength = u32(data, offset + 4, order)
            if (blockLength < 12 || blockLength > data.size - offset) break
            when (type) {
                1L -> if (blockLength >= 20) interfaces.add(u16(data, offset + 8, order).toLong())
                6L -> if (blockLength >= 32) {
                    val id = u32(data, offset + 8, order).toInt()
                    val captured = u32(data, offset + 20, order)
                    val link = interfaces.getOrNull(id) ?: -1L
                    if (captured >= 0 && captured <= blockLength - 32) {
                        parsePacket(data, offset + 28, captured, link, found)
                    }
                }
                3L -> if (blockLength >= 16 && interfaces.isNotEmpty()) {
                    val original = u32(data, offset + 8, order)
                    val captured = minOf(original, blockLength - 16)
                    parsePacket(data, offset + 12, captured, interfaces[0], found)
                }
            }
            offset += blockLength
        }
        return found
    }

    private fun parsePacket(data: ByteArray, start: Int, length: Long, link: Long, found: MutableSet<String>) {
        if (length <= 0 || start < 0 || start + length > data.size) return
        var pos = start
        val end = start + length.toInt()
        var etherType = -1
        when (link) {
            1L -> {
                if (pos + 14 > end) return
                etherType = u16(data, pos + 12, ByteOrder.BIG_ENDIAN)
                pos += 14
                while (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100) {
                    if (pos + 4 > end) return
                    etherType = u16(data, pos + 2, ByteOrder.BIG_ENDIAN)
                    pos += 4
                }
            }
            101L, 12L -> {
                val version = (data[pos].toInt() ushr 4) and 0x0f
                etherType = if (version == 4) 0x0800 else if (version == 6) 0x86dd else -1
            }
            113L -> {
                if (pos + 16 > end) return
                etherType = u16(data, pos + 14, ByteOrder.BIG_ENDIAN)
                pos += 16
            }
            276L -> {
                if (pos + 20 > end) return
                etherType = u16(data, pos, ByteOrder.BIG_ENDIAN)
                pos += 20
            }
            else -> return
        }
        when (etherType) {
            0x0800 -> {
                if (pos + 20 > end) return
                val ihl = (data[pos].toInt() and 0x0f) * 4
                if (ihl < 20 || pos + ihl > end) return
                val src = ipv4(data, pos + 12)
                val dst = ipv4(data, pos + 16)
                if (isPublicV4(src)) found.add(src)
                if (isPublicV4(dst)) found.add(dst)
            }
            0x86dd -> {
                if (pos + 40 > end || (data[pos].toInt() ushr 4 and 0x0f) != 6) return
                val src = data.copyOfRange(pos + 8, pos + 24)
                val dst = data.copyOfRange(pos + 24, pos + 40)
                publicV6(src)?.let { found.add(it) }
                publicV6(dst)?.let { found.add(it) }
            }
        }
    }

    private fun ipv4(b: ByteArray, p: Int) =
        (b[p].toInt() and 255).toString() + "." +
        (b[p + 1].toInt() and 255) + "." +
        (b[p + 2].toInt() and 255) + "." +
        (b[p + 3].toInt() and 255)

    private fun isPublicV4(ip: String): Boolean {
        val a = ip.split(".").map { it.toInt() }
        val x = a[0]; val y = a[1]
        return !(x == 0 || x == 10 || x == 127 || x >= 224 ||
            (x == 100 && y in 64..127) ||
            (x == 169 && y == 254) ||
            (x == 172 && y in 16..31) ||
            (x == 192 && y == 168) ||
            (x == 192 && y == 0) ||
            (x == 198 && y in 18..19))
    }

    private fun publicV6(bytes: ByteArray): String? {
        if (bytes.size != 16) return null
        val first = bytes[0].toInt() and 255
        if (first !in 0x20..0x3f) return null
        return try { InetAddress.getByAddress(bytes).hostAddress?.substringBefore("%") } catch (_: Exception) { null }
    }

    private fun u16(b: ByteArray, p: Int, order: ByteOrder): Int =
        ByteBuffer.wrap(b, p, 2).order(order).short.toInt() and 0xffff

    private fun u32(b: ByteArray, p: Int, order: ByteOrder): Long =
        ByteBuffer.wrap(b, p, 4).order(order).int.toLong() and 0xffffffffL
}
