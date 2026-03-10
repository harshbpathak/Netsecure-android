package com.example.netsecure.network

import com.example.netsecure.network.model.AnalysisRequest
import com.example.netsecure.network.model.AnalysisResponse
import com.example.netsecure.network.model.AvailabilityRequest
import com.example.netsecure.network.model.AvailabilityResponse
import com.example.netsecure.network.model.JobListResponse
import com.example.netsecure.network.model.JobResult
import com.example.netsecure.network.model.MultiAnalysisResponse
import com.example.netsecure.network.model.MultiObservableRequest
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the IntelOwl REST API.
 * Authentication is handled by the OkHttp interceptor in [IntelOwlConfig.buildService].
 *
 * All endpoints return [Response<T>] so callers can inspect HTTP error codes
 * (e.g. 429 Too Many Requests → trigger backoff).
 */
interface IntelOwlApiService {

    /**
     * Analyze a single observable (IP / domain / hash).
     * POST /api/analyze_observable
     */
    @POST("api/analyze_observable")
    suspend fun analyzeObservable(
        @Body request: AnalysisRequest
    ): Response<AnalysisResponse>

    /**
     * Analyze multiple observables of the same classification in a single batch call.
     * POST /api/analyze_multiple_observables
     *
     * IMPORTANT: All observables in a single call must have the same classification.
     * Split IPs / domains / hashes into separate calls.
     */
    @POST("api/analyze_multiple_observables")
    suspend fun analyzeMultipleObservables(
        @Body request: MultiObservableRequest
    ): Response<MultiAnalysisResponse>

    /**
     * Poll for the result of a submitted analysis job.
     * GET /api/jobs/{job_id}
     */
    @GET("api/jobs/{job_id}")
    suspend fun getJob(
        @Path("job_id") jobId: Int
    ): Response<JobResult>

    /**
     * Check if IntelOwl already has a cached analysis for the observable's MD5.
     * POST /api/ask_analysis_availability
     * Returns job_id if a recent analysis exists — allows reusing results without re-submitting.
     */
    @POST("api/ask_analysis_availability")
    suspend fun askAnalysisAvailability(
        @Body request: AvailabilityRequest
    ): Response<AvailabilityResponse>

    /**
     * Fetch paginated job history from IntelOwl.
     * GET /api/jobs?page=1&page_size=50
     * Used by ThreatIntelligenceScreen to populate the history table.
     */
    @GET("api/jobs")
    suspend fun getJobs(
        @Query("page") page: Int = 1,
        @Query("page_size") pageSize: Int = 50
    ): Response<JobListResponse>

    /**
     * Health-check endpoint used by the Settings screen "Test Connection" button.
     * GET /api/tags — works across all IntelOwl versions.
     */
    @GET("api/tags")
    suspend fun analyzerHealthcheck(): Response<Any>
}
