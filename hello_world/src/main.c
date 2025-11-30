/*
 * Copyright 2020 The TensorFlow Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "main_functions.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "tfm_ns_interface.h"
#ifdef TFM_PSA_API
#include "psa_manifest/sid.h"
#include "psa/crypto.h"
#endif

#include "dummy_partition.h"


/* Increase number of loops to see full period of the sine curve */
#define NUM_LOOPS 10

/**
 * \brief Retrieve the version of the PSA Framework API.
 *
 * \note This is a functional test only and doesn't
 *       mean to test all possible combinations of
 *       input parameters and return values.
 */
static void tfm_get_version(void)
{
	uint32_t version;

	version = psa_framework_version();
	if (version == PSA_FRAMEWORK_VERSION) {
		printk("The version of the PSA Framework API is %d.\n",
		       version);
	} else {
		printk("The version of the PSA Framework API is not valid!\n");
		return;
	}
}

#ifdef TFM_PSA_API
/**
 * \brief Retrieve the minor version of a RoT Service.
 */
static void tfm_get_sid(void)
{
	uint32_t version;

	version = psa_version(TFM_CRYPTO_SID);
	if (version == PSA_VERSION_NONE) {
		printk("RoT Service is not implemented or caller is not ");
		printk("authorized to access it!\n");
		return;
	}

	/* Valid version number */
	printk("The PSA Crypto service minor version is %d.\n", version);
}

/**
 * \brief Generates random data using the TF-M crypto service.
 */
void tfm_psa_crypto_rng(void)
{
	psa_status_t status;
	uint8_t outbuf[256] = { 0 };

	status = psa_generate_random(outbuf, 256);
	printk("Generating 256 bytes of random data:");
	for (uint16_t i = 0; i < 256; i++) {
		if (!(i % 16)) {
			printk("\n");
		}
		printk("%02X ", (uint8_t)(outbuf[i] & 0xFF));
	}
	printk("\n");
}
#endif

/* This is the default main used on systems that have the standard C entry
 * point. Other devices (for example FreeRTOS or ESP32) that have different
 * requirements for entry code (like an app_main function) should specialize
 * this main.cc file in a target-specific subfolder.
 */

uint32_t test_var = 0x12345678;
uint32_t test_var2 = 0xabcdef00;

// allocate 64KB to flash
static const uint8_t tmp[0x10000] = {0};
int main(int argc, char *argv[])
{
	setup();
	/* Note: Modified from original while(true) to accommodate CI */
	for (int i = 0; i < NUM_LOOPS; i++) {
		loop();
	}

	printk("TF-M IPC on %s\n", CONFIG_BOARD);

	tfm_get_version();
#ifdef TFM_PSA_API
	tfm_get_sid();
	tfm_psa_crypto_rng();
#endif

	printk("Accessing secure SRAM...\n");

	printk("Initial test_var at address: 0x%08x: 0x%x\n", (uint32_t)&test_var, test_var);

	printk("Initial test_var2 at address: 0x%08x: 0x%x\n", (uint32_t)&test_var2, test_var2);

	uint32_t sram_addr = SRAM1_BASE; // + GTZC_MPCBB_SUPERBLOCK_SIZE*12;
	printk("Read from secure SRAM address 0x%x: 0x%08x\n", sram_addr, *((uint32_t*) sram_addr));
	*((uint32_t*) sram_addr) = 0xABABABAB;

	uint8_t digest[32];

	//for (int key = 0; key < 6; key++) {
		int key = 0;
		psa_status_t status = dp_secret_digest(key, digest, sizeof(digest));

		if (status == PSA_ERROR_INVALID_ARGUMENT && key == 5) {
			printk("No valid secret for key, received expected error code\n");
		} else if (status != PSA_SUCCESS) {
			printk("Status: %d\n", status);
		} else {
			printk("Digest: ");
			for (int i = 0; i < 32; i++) {
				printk("%02x", digest[i]);
			}
			printk("\n");
		}
	//}

	printk("read tmp at idx digest[0]: 0x%02x\n", tmp[digest[0]]);

	volatile uint32_t *ptr = (volatile uint32_t *)SRAM1_BASE;

	printk("Attempting write to %p\n", ptr);

	*ptr = 0xDEADBEEF;

	printk("Write finished\n");

	printk("Reading: 0x%08x\n", *ptr);


	printk("Read again from secure SRAM address: 0x%08x\n", *((uint32_t*) sram_addr));

	*((uint32_t*) sram_addr) = 0xCDCDCDCD;

	printk("Read again from secure SRAM address: 0x%08x\n", *((uint32_t*) sram_addr));

	return 0;
}
