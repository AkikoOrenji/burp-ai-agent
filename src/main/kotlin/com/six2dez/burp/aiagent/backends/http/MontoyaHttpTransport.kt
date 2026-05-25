package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.backends.HealthCheckResult

data class TransportResponse(
    val statusCode: Int,
    val body: String,
    val isSuccessful: Boolean,
)

class MontoyaHttpTransport(
    private val api: MontoyaApi,
) {
    fun post(
        url: String,
        headers: Map<String, String>,
        jsonBody: String,
        timeoutMs: Long = 120_000,
    ): TransportResponse {
        val bodyBytes = burp.api.montoya.core.ByteArray.byteArray(*jsonBody.toByteArray(Charsets.UTF_8))
        val target = prepareRequestTarget(url)
        var request =
            HttpRequest
                .httpRequest(target.service, requestTemplate("POST", target))
                .withBody(bodyBytes)
                .withAddedHeader("Content-Type", "application/json; charset=utf-8")
        headers.forEach { (name, value) ->
            request = request.withAddedHeader(name, value)
        }
        return execute(request, timeoutMs)
    }

    fun get(
        url: String,
        headers: Map<String, String>,
        timeoutMs: Long = 3_000,
    ): TransportResponse {
        val target = prepareRequestTarget(url)
        var request = HttpRequest.httpRequest(target.service, requestTemplate("GET", target))
        headers.forEach { (name, value) ->
            request = request.withAddedHeader(name, value)
        }
        return execute(request, timeoutMs)
    }

    fun healthCheckGet(
        url: String,
        headers: Map<String, String>,
        timeoutMs: Long = 3_000,
    ): HealthCheckResult =
        try {
            val resp = get(url, headers, timeoutMs)
            when {
                resp.isSuccessful -> HealthCheckResult.Healthy
                resp.statusCode == 401 || resp.statusCode == 403 ->
                    HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${resp.statusCode}).")
                else -> HealthCheckResult.Unavailable("HTTP ${resp.statusCode}.")
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Request failed")
        }

    private fun prepareRequestTarget(url: String): RequestTarget {
        val uri = java.net.URI(url)
        val scheme = uri.scheme ?: "http"
        val host = uri.host ?: uri.authority ?: throw IllegalArgumentException("Invalid URL: $url")
        val usesHttps = scheme.equals("https", ignoreCase = true)
        val port = if (uri.port == -1) defaultPortForScheme(scheme) else uri.port
        return RequestTarget(
            service = HttpService.httpService(host, port, usesHttps),
            requestTarget = buildOriginFormTarget(uri),
            hostHeader = buildHostHeader(host, port, usesHttps),
        )
    }

    private fun execute(
        request: HttpRequest,
        timeoutMs: Long,
    ): TransportResponse {
        val options =
            RequestOptions
                .requestOptions()
                .withHttpMode(HttpMode.HTTP_1)
                .withUpstreamTLSVerification()
                .withResponseTimeout(timeoutMs)
        return try {
            val result = api.http().sendRequest(request, options)
            decodeResponse(result.response())
        } catch (e: Exception) {
            val service = runCatching { request.httpService().toString() }.getOrDefault("<unknown-service>")
            val path = runCatching { request.path() }.getOrDefault("<unknown-path>")
            api.logging().logToError("[MontoyaHttpTransport] send failed service=$service path=$path mode=HTTP_1: ${e.message}")
            throw e
        }
    }

    private data class RequestTarget(
        val service: HttpService,
        val requestTarget: String,
        val hostHeader: String,
    )

    companion object {
        internal fun buildOriginFormTarget(uri: java.net.URI): String {
            val path = uri.rawPath?.ifEmpty { "/" } ?: "/"
            val query = uri.rawQuery?.let { "?$it" }.orEmpty()
            return path + query
        }

        internal fun buildHostHeader(
            host: String,
            port: Int,
            usesHttps: Boolean,
        ): String {
            val normalizedHost = normalizeHostHeaderHost(host)
            val isDefaultPort = port == if (usesHttps) 443 else 80
            return if (isDefaultPort) normalizedHost else "$normalizedHost:$port"
        }

        private fun requestTemplate(
            method: String,
            target: RequestTarget,
        ): String = "$method ${target.requestTarget} HTTP/1.1\r\nHost: ${target.hostHeader}\r\n\r\n"

        private fun defaultPortForScheme(scheme: String): Int = if (scheme.equals("https", ignoreCase = true)) 443 else 80

        private fun normalizeHostHeaderHost(host: String): String =
            if (host.contains(':') && !host.startsWith('[') && !host.endsWith(']')) {
                "[$host]"
            } else {
                host
            }

        // Force UTF-8: Montoya's bodyToString() decodes with the JVM platform charset, which mojibakes
        // multibyte responses (e.g. Chinese, emoji) on hosts whose default charset isn't UTF-8.
        // OpenAI-compatible servers commonly return Content-Type: application/json without an explicit
        // charset parameter, so we cannot rely on the server-declared charset either.
        internal fun decodeResponse(response: HttpResponse?): TransportResponse {
            val code = response?.statusCode()?.toInt() ?: 0
            val body = response?.body()?.bytes?.toString(Charsets.UTF_8) ?: ""
            return TransportResponse(
                statusCode = code,
                body = body,
                isSuccessful = code in 200..299,
            )
        }
    }
}
