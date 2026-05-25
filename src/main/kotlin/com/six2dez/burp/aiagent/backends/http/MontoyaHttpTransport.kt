package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
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
        // Associate an explicit HttpService with the request so Burp's upstream proxy
        // settings are applied when the request is sent via Montoya.
        val uri = java.net.URI(url)
        val scheme = uri.scheme ?: "http"
        val host = uri.host ?: uri.authority ?: throw IllegalArgumentException("Invalid URL: $url")
        val port = if (uri.port == -1) if (scheme.equals("https", ignoreCase = true)) 443 else 80 else uri.port
        val service = HttpService.httpService(host, port, scheme.equals("https", ignoreCase = true))
        var request =
            HttpRequest
                .httpRequestFromUrl(url)
                .withService(service)
                .withMethod("POST")
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
        val uri = java.net.URI(url)
        val scheme = uri.scheme ?: "http"
        val host = uri.host ?: uri.authority ?: throw IllegalArgumentException("Invalid URL: $url")
        val port = if (uri.port == -1) if (scheme.equals("https", ignoreCase = true)) 443 else 80 else uri.port
        val service = HttpService.httpService(host, port, scheme.equals("https", ignoreCase = true))
        var request = HttpRequest.httpRequestFromUrl(url).withService(service)
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

    private fun execute(
        request: HttpRequest,
        timeoutMs: Long,
    ): TransportResponse {
        val options =
            RequestOptions
                .requestOptions()
                .withUpstreamTLSVerification()
                .withResponseTimeout(timeoutMs)
        val result = api.http().sendRequest(request, options)
        return decodeResponse(result.response())
    }

    companion object {
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
