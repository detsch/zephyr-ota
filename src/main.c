/*
 * Copyright (c) 2021 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(aknano_sample);

#include <zephyr.h>
#include <sys/printk.h>
#include <logging/log_ctrl.h>
#include <device.h>
#include <devicetree.h>
#include <drivers/gpio.h>
#include <linker/sections.h>
#include <errno.h>
#include <stdio.h>

#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/net_mgmt.h>

#include "lib/aknano.h"
#include "mqtt_publisher.h""


#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/* 1000 msec = 1 sec */
#define READ_BUTTON_SLEEP_TIME_MS   1000

/* scheduling priority used by each thread */
#define PRIORITY 7

static void read_button_loop(void)
{
	const struct device *dev;
	int button_state = 0;
	int ret = 0;

	LOG_INF("Button: %s", DT_GPIO_LABEL(DT_ALIAS(sw0), gpios));
	dev = device_get_binding(DT_GPIO_LABEL(DT_ALIAS(sw0), gpios));
	if (dev == NULL) {
		LOG_ERR("Unable to get button device");
		return;
	}

	while (1) {
		button_state = gpio_pin_get(dev, DT_GPIO_PIN(DT_ALIAS(sw0), gpios));
		LOG_INF("button_state=%d", button_state);
		k_msleep(READ_BUTTON_SLEEP_TIME_MS);
	}
}

void main_thread(void)
{
	LOG_INF(
		ANSI_COLOR_GREEN "* Starting binary compiled at " 
		__DATE__ " " __TIME__ ANSI_COLOR_RESET "\n" );

	aknano_init();
	aknano_autohandler();
	LOG_INF("Back to main loop");
	k_sleep(K_FOREVER);
}

#define STACKSIZE 4096

K_THREAD_DEFINE(blink_led_id, STACKSIZE, read_button_loop, NULL, NULL, NULL,
 		PRIORITY, 0, 0);

K_THREAD_DEFINE(main_thread_id, STACKSIZE, main_thread, NULL, NULL, NULL,
		-1, 0, 0);

K_THREAD_DEFINE(mqtt_app_id, STACKSIZE, mqtt_start_app, NULL, NULL, NULL,
 		PRIORITY, 0, 0);
