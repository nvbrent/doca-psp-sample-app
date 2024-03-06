/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <algorithm>
#include <locale.h>
#include <vector>

#include <doca_flow_crypto.h>
#include <doca_log.h>
#include <rte_cycles.h>

#include <psp_gw_bench.h>
#include <psp_gw_flows.h>

DOCA_LOG_REGISTER(PSP_BENCH);

extern volatile bool force_quit; // Set when signal is received

/**
 * @brief Programs a PSP encryption SPI/Key pair and creates a flow which references the
 *        pair to perform PSP tunnel encapsulation and encryption
 *
 * @loops [in]: The number of loops to execute
 * @psp_flows [in]: The object which manages the doca resources
 * @return: DOCA_SUCCESS on success (timing result is valid); DOCA_ERROR otherwise
 */
static doca_error_t execute_psp_flow_create_loop(size_t loops, PSP_GatewayFlows *psp_flows)
{
	std::vector<psp_session_t> sessions;
	sessions.reserve(loops);

	struct psp_session_t session = {
		.dst_mac = {{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}},
		.dst_pip =
			{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
		.dst_vip = 0x0,
		.spi = 0x0,
		.crypto_id = 0x1,
		.vc = 0x0,
	};
	uint32_t encrypt_key[256 / 32] = {};

	doca_error_t result = DOCA_SUCCESS;

	for (size_t i = 0; i < loops && !force_quit; i++) {
		session.dst_vip = RTE_BE32(i + 0x10101010);
		session.spi = i + 1000;
		session.crypto_id = 1;
		session.vc = 0x8000000000000000 + (i << 32) + i;
		result = psp_flows->add_encrypt_entry(&session, encrypt_key);

		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("PSP Encrypt Flow creation failed: %s", doca_error_get_descr(result));
			break;
		}

		sessions.push_back(session);
	}

	for (auto &session_to_remove : sessions) {
		psp_flows->remove_encrypt_entry(&session_to_remove);
	}

	return result;
}

/**
 * @brief Executes a benchmark of PSP flow insertion for encrypting/encapping flows
 *
 * @warmup_loops [in]: The number of loops to execute before timing starts
 * @timed_loops [in]: The number of loops to execute and time
 * @psp_flows [in]: The object which manages the doca resources
 * @return: DOCA_SUCCESS on success (benchmark completed); DOCA_ERROR otherwise
 */
static doca_error_t run_benchmark_psp_flow_create(size_t warmup_loops, size_t timed_loops, PSP_GatewayFlows *psp_flows)
{
	doca_error_t result;

	printf("Testing psp flow insertions for %ld loops...\n", timed_loops);

	result = execute_psp_flow_create_loop(warmup_loops, psp_flows);
	if (result != DOCA_SUCCESS) {
		return result;
	}

	uint64_t tstart = rte_get_tsc_cycles();
	result = execute_psp_flow_create_loop(timed_loops, psp_flows);
	uint64_t duration = rte_get_tsc_cycles() - tstart;

	if (force_quit) {
		printf("Benchmark aborted\n");
		return DOCA_ERROR_SHUTDOWN;
	}

	double to_sec = 1.0 / rte_get_tsc_hz();
	double dur_sec = duration * to_sec;
	printf("num loops, %ld, duration, %g, Kilo-Inserts-per-sec, %0.1f\n",
	       timed_loops,
	       dur_sec,
	       1e-3 * timed_loops / dur_sec);

	return DOCA_SUCCESS;
}

/**
 * @brief Constructs a PSP bulk object and executes a key generation benchmark
 *
 * @bsize [in]: The bulk size to test
 * @loops [in]: The number of loops to execute
 * @spi_key_bulk [in]: The object which generates keys
 * @return: DOCA_SUCCESS on success (keys were generated successfully; timing results are valid); DOCA_ERROR otherwise
 */
static doca_error_t execute_tx_key_gen_loop(size_t bsize,
					    size_t loops,
					    struct doca_flow_crypto_psp_spi_key_bulk *spi_key_bulk)
{
	doca_error_t result = DOCA_SUCCESS;
	uint32_t key_buffer[256 / 32];
	uint32_t spi;

	for (size_t i = 0; i < loops && !force_quit; i++) {
		result = doca_flow_crypto_psp_spi_key_bulk_generate(spi_key_bulk);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to generate bulk of size %ld: %s", bsize, doca_error_get_descr(result));
			return result;
		}

		for (size_t key_idx = 0; key_idx < bsize && !force_quit; key_idx++) {
			result = doca_flow_crypto_psp_spi_key_bulk_get(spi_key_bulk, key_idx, &spi, key_buffer);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Failed to get key from bulk of size %ld: %s",
					     bsize,
					     doca_error_get_descr(result));
				return result;
			}
		}
	}
	return DOCA_SUCCESS;
}

/**
 * @brief Executes a benchmark on the bulk generation of PSP encryption keys
 *        for the given key size over the given number of loops.
 *
 * @bulk_sizes [in]: The list of bulk sizes to benchmark
 * @warmup_loops [in]: The number of loops to execute before timing starts
 * @timed_loops [in]: The number of loops to execute and time
 * @key_type [in]: Indicates the key size to generate
 * @port [in]: The device which will generate the keys
 * @return: DOCA_SUCCESS on success (timing results are valid); DOCA_ERROR otherwise
 */
static doca_error_t run_benchmark_tx_key_gen(const std::vector<size_t> &bulk_sizes,
					     size_t warmup_loops,
					     size_t timed_loops,
					     enum doca_flow_crypto_key_type key_type,
					     doca_flow_port *port)
{
	if (bulk_sizes.empty()) {
		return DOCA_SUCCESS;
	}
	std::vector<uint64_t> durations;
	durations.reserve(bulk_sizes.size());

	for (size_t bsize : bulk_sizes) {
		printf("Testing bulk size %ld...\n", bsize);
		if (force_quit)
			break;

		struct doca_flow_crypto_psp_spi_key_bulk *spi_key_bulk;
		doca_error_t result = doca_flow_crypto_psp_spi_key_bulk_alloc(port, key_type, bsize, &spi_key_bulk);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate bulk of size %ld: %s", bsize, doca_error_get_descr(result));
			return result;
		}

		result = execute_tx_key_gen_loop(bsize, warmup_loops, spi_key_bulk);
		if (result != DOCA_SUCCESS) {
			return result;
		}

		uint64_t tstart = rte_get_tsc_cycles();
		result = execute_tx_key_gen_loop(bsize, timed_loops, spi_key_bulk);
		uint64_t tend = rte_get_tsc_cycles();

		durations.push_back(tend - tstart);

		doca_flow_crypto_psp_spi_key_bulk_free(spi_key_bulk);
	}

	if (force_quit) {
		printf("Benchmark aborted\n");
		return DOCA_ERROR_SHUTDOWN;
	}

	printf("Key size: %d\n", key_type == DOCA_FLOW_CRYPTO_KEY_128 ? 128 : 256);
	double to_sec = 1.0 / rte_get_tsc_hz();
	for (size_t i = 0; i < bulk_sizes.size(); i++) {
		size_t bsize = bulk_sizes[i];
		double dur_sec = durations[i] * to_sec;
		printf("Bulk Size, %ld, duration, %g, Kilo-KPS, %0.1f\n",
		       bsize,
		       dur_sec,
		       1e-3 * bsize * timed_loops / dur_sec);
	}

	return DOCA_SUCCESS;
}

doca_error_t psp_gw_run_benchmarks(PSP_GatewayFlows *psp_flows)
{
	struct doca_flow_port *port = psp_flows->pf()->port_obj;
	std::vector<size_t> bulk_sizes;
	for (size_t i = 1; i <= 64; i *= 2)
		bulk_sizes.push_back(i);

	run_benchmark_psp_flow_create(16, 50000, psp_flows);
	run_benchmark_tx_key_gen(bulk_sizes, 16, 10000, DOCA_FLOW_CRYPTO_KEY_128, port);
	run_benchmark_tx_key_gen(bulk_sizes, 16, 10000, DOCA_FLOW_CRYPTO_KEY_256, port);

	return DOCA_SUCCESS;
}
