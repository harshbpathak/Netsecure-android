package com.example.netsecure.network.model

import com.google.gson.JsonElement
import com.google.gson.annotations.SerializedName

// ── Request Models ──

data class AnalysisRequest(
    @SerializedName("observable_name") val observableName: String,
    @SerializedName("observable_classification") val observableClassification: String,
    @SerializedName("analyzers_requested") val analyzersRequested: List<String>,
    @SerializedName("tlp") val tlp: String = "AMBER",
    @SerializedName("runtime_configuration") val runtimeConfiguration: Map<String, Any> = emptyMap()
)

data class MultiObservableRequest(
    @SerializedName("observables") val observables: List<List<String>>, // [[classification, name], ...]
    @SerializedName("analyzers_requested") val analyzersRequested: List<String>,
    @SerializedName("tlp") val tlp: String = "AMBER"
)

data class AvailabilityRequest(
    @SerializedName("md5") val md5: String,
    @SerializedName("analyzers") val analyzers: List<String>,
    @SerializedName("minutes_ago") val minutesAgo: Int = 60
)

// ── Response Models ──

data class AnalysisResponse(
    @SerializedName("job_id") val jobId: Int? = null,
    @SerializedName("status") val status: String? = null,
    // For multi-observable, returns list of job responses
    @SerializedName("count") val count: Int? = null
)

data class MultiAnalysisResponse(
    @SerializedName("count") val count: Int,
    @SerializedName("results") val results: List<AnalysisResponse>
)

data class AvailabilityResponse(
    @SerializedName("status") val status: String? = null,  // "exists" or null
    @SerializedName("job_id") val jobId: Int? = null,
    @SerializedName("job_ids") val jobIds: List<Int>? = null
)

// ── Job Result Models ──

data class JobResult(
    @SerializedName("id")                         val id: Int,
    @SerializedName("status")                     val status: String,
    @SerializedName("observable_name")            val observableName: String,
    @SerializedName("observable_classification")  val observableClassification: String,
    @SerializedName("md5")                        val md5: String? = null,
    @SerializedName("errors")                     val errors: List<String>? = null,
    @SerializedName("analyzer_reports")           val analyzerReports: List<AnalyzerReport>? = null,
    @SerializedName("received_request_time")      val receivedRequestTime: String? = null,
    @SerializedName("finished_analysis_time")     val finishedAnalysisTime: String? = null,
    @SerializedName("data_model")                 val dataModel: JobDataModel? = null
) {
    // Convenience: expose the data_model evaluation for fallback scoring
    val rawJson: com.google.gson.JsonElement? get() = null  // kept for backward-compat, use dataModel instead

    fun isTerminal(): Boolean = status in listOf(
        "reported_without_fails", "reported_with_fails", "failed", "killed"
    )
    fun isSuccess(): Boolean = status in listOf("reported_without_fails", "reported_with_fails")
}

data class JobDataModel(
    @SerializedName("evaluation")     val evaluation: String? = null,
    @SerializedName("tags")           val tags: List<String>? = null,
    @SerializedName("country_code")   val countryCode: String? = null,
    @SerializedName("isp")            val isp: String? = null
)


/**
 * A single analyzer's report within a job.
 * The [report] field is kept as JsonElement because each analyzer returns
 * a completely different JSON structure (object, array, or primitive).
 */
data class AnalyzerReport(
    @SerializedName("name") val name: String,
    @SerializedName("status") val status: String,        // "success","failed","running"
    @SerializedName("report") val report: JsonElement? = null,
    @SerializedName("errors") val errors: List<String>? = null,
    @SerializedName("type") val type: String? = null     // "analyzer"
) {
    /** Safe string extraction for a specific field in the analyzer's report JsonObject */
    fun getReportField(fieldName: String): String? {
        return try {
            report?.asJsonObject?.get(fieldName)?.asString
        } catch (_: Exception) { null }
    }

    fun getReportDouble(fieldName: String): Double? {
        return try {
            report?.asJsonObject?.get(fieldName)?.asDouble
        } catch (_: Exception) { null }
    }

    fun getReportInt(fieldName: String): Int? {
        return try {
            report?.asJsonObject?.get(fieldName)?.asInt
        } catch (_: Exception) { null }
    }

    fun getReportBoolean(fieldName: String): Boolean? {
        return try {
            report?.asJsonObject?.get(fieldName)?.asBoolean
        } catch (_: Exception) { null }
    }
}

// ── Job List (GET /api/jobs) ──

data class JobListResponse(
    @SerializedName("count")   val count: Int,
    @SerializedName("results") val results: List<JobListItem>
)

data class JobListItem(
    @SerializedName("id")                         val id: Int,
    @SerializedName("status")                     val status: String,
    @SerializedName("observable_name")            val observableName: String,
    @SerializedName("observable_classification")  val observableClassification: String,
    @SerializedName("md5")                        val md5: String? = null,
    @SerializedName("tlp")                        val tlp: String? = null,
    @SerializedName("received_request_time")      val receivedRequestTime: String? = null,
    @SerializedName("finished_analysis_time")     val finishedAnalysisTime: String? = null,
    @SerializedName("process_time")               val processTime: Double? = null,
    @SerializedName("errors")                     val errors: List<String>? = null,
    @SerializedName("tags")                       val tags: List<Any>? = null
) {
    fun isSuccess(): Boolean = status in listOf("reported_without_fails", "reported_with_fails")
    fun isTerminal(): Boolean = status in listOf(
        "reported_without_fails", "reported_with_fails", "failed", "killed"
    )
}
