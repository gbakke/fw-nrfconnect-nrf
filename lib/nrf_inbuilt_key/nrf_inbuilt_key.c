/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/

#include <at_cmd.h>
#include <at_cmd_parser/at_cmd_parser.h>
#include <at_cmd_parser/at_params.h>
#include <bsd_limits.h>
#include <nrf_inbuilt_key.h>
#include <stdio.h>
#include <string.h>
#include <zephyr.h> // errno values.

#define NRF_INBUILT_KEY_OP_LS "AT%CMNG=1"
#define NRF_INBUILT_KEY_OP_RD "AT%CMNG=2"

#if CONFIG_NRF_INBUILT_KEY_AUTHETICATED
// When signing with AT%XSUDO (two at commands in one message),
// there should not be an AT prefix on the second command.
#define NRF_INBUILT_KEY_OP_WR "%CMNG=0"
#define NRF_INBUILT_KEY_OP_RM "%CMNG=3"
#define AUTHENTICATED_AT_CMD_SIGNATURE_SIZE (128)
#else
#define NRF_INBUILT_KEY_OP_WR "AT%CMNG=0"
#define NRF_INBUILT_KEY_OP_RM "AT%CMNG=3"
#endif

#define NRF_INBUILT_KEY_CHAR_SIZE_MAX_INT32 (10)
#define NRF_INBUILT_KEY_CR_CHAR_SIZE (1)
#define NRF_INBUILT_KEY_LF_CHAR_SIZE (1)
#define NRF_INBUILT_KEY_QUOTES_CHAR_SIZE (1)
#define NRF_INBUILT_KEY_ZERO_TERMINATOR_SIZE (1)
#define NRF_INBUILT_KEY_COMMA_SIZE (1)
#define NRF_INBUILT_KEY_INVALID_HANDLE (-1)

static uint8_t scratch_buf[4096];
static char at_cmee_strings[2][10] = {"AT+CMEE=0", "AT+CMEE=1"};

static int cmee_active(void)
{
	char response[sizeof("+CMEE: X\r\n") + 1];
	memset(response, 0, sizeof(response));

	enum at_cmd_state state;

	int retval =
		at_cmd_write("AT+CMEE?", response, sizeof(response), &state);
	if (retval == 0) {
		char *deactivated = strchr(&response[6], '0');
		if (deactivated != NULL) {
			return 0;
		}
		char *activated = strchr(&response[6], '1');
		if (activated != NULL) {
			return 1;
		}
	}

	return -EIO;
}

static int cmee_set(bool enable)
{
	char response[10];
	enum at_cmd_state state;

	int retval = at_cmd_write(at_cmee_strings[(int)enable], response,
				  sizeof(response), &state);

	if (retval < 0) {
		return -EIO;
	}

	return 0;
}
uint32_t nrf_inbuilt_key_init(void)
{
#if CONFIG_NRF_INBUILT_KEY_AUTHENTICATED
	int retval = authenticated_atcmd_init();
	if (retval != 0) {
		return -EFAULT;
	}
#endif
	return 0;
}

uint32_t nrf_inbuilt_key_deinit(void)
{
#if CONFIG_NRF_INBUILT_KEY_AUTHENTICATED
	authenticated_atcmd_deinit();
#endif
	return 0;
}

static int translate_error(int err)
{
	switch (err) {
	case 513:
		return -ENOENT;
		break;
	case 514:
		return -EPERM;
		break;
	case 515:
		return -ENOMEM;
		break;
	case 518:
		return -EACCES;
		break;
	default:
		return -EFAULT;
		break;
	}
}

int nrf_inbuilt_key_write(nrf_sec_tag_t sec_tag,
			  nrf_key_mgnt_cred_type_t cred_type, uint8_t *p_buffer,
			  uint16_t buffer_len)
{
	if ((p_buffer == NULL) || (buffer_len == 0)) {
		return -EINVAL;
	}

	// Allocate the maximum possible length. Content has to be inside double
	// quotes.
	uint16_t scratch_buf_len = sizeof(NRF_INBUILT_KEY_OP_WR) + buffer_len +
				   (NRF_INBUILT_KEY_CHAR_SIZE_MAX_INT32 * 2) +
				   (NRF_INBUILT_KEY_COMMA_SIZE * 3) +
				   (NRF_INBUILT_KEY_QUOTES_CHAR_SIZE * 2) +
				   NRF_INBUILT_KEY_CR_CHAR_SIZE +
				   NRF_INBUILT_KEY_LF_CHAR_SIZE +
				   NRF_INBUILT_KEY_ZERO_TERMINATOR_SIZE;

#ifdef CONFIG_NRF_INBUILT_KEY_AUTHENTICATED
	// Note: The actual command is populated after the signature as this is
	// an authenticate command.
	uint8_t *p_cmd = &scratch_buf[AUTHENTICATED_AT_CMD_SIGNATURE_SIZE];
	uint8_t *p_signature = scratch_buf;
#else
	uint8_t *p_cmd = &scratch_buf[0];
#endif

	memset(p_cmd, 0, scratch_buf_len);

	int exp_len = snprintf((char *)p_cmd, scratch_buf_len, "%s,%u,%u,\"",
			       NRF_INBUILT_KEY_OP_WR, (uint32_t)sec_tag,
			       (uint8_t)cred_type);

	memcpy(&p_cmd[exp_len], p_buffer, buffer_len);
	exp_len += buffer_len;

	memcpy(&p_cmd[exp_len], "\"\r\n", 4);
	exp_len += 4;

	if (exp_len >= scratch_buf_len) {
		return -ENOBUFS;
	}

	size_t expected_size = strlen((char *)p_cmd);
	expected_size +=
		NRF_INBUILT_KEY_ZERO_TERMINATOR_SIZE; // Not sure if this is
						      // needed!
	int retval = 0;

#ifdef CONFIG_NRF_INBUILT_KEY_AUTHENTICATED
	retval = authenticated_atcmd_sign(p_cmd, expected_size, p_signature);

	expected_size +=
		AUTHENTICATED_AT_CMD_SIGNATURE_SIZE; // Include the length for
						     // the signature when
						     // writing to the AT
						     // interface.
#else
	(void)expected_size;
#endif

	if (retval == 0) {
		bool cmee_activated = false;
		int cmee_active_result = cmee_active();

		if (cmee_active_result < 0) {
			// Could not activate CMEE.
			return -EFAULT;
		}

		if (cmee_active_result == 0) {
			cmee_set(true);
			cmee_activated = true;
		}

		enum at_cmd_state state;
		int result = at_cmd_write(scratch_buf, scratch_buf,
					  scratch_buf_len, &state);
		if (cmee_activated) {
			cmee_set(false);
		}

		if ((result != 0) && (state == AT_CMD_ERROR_CME)) {
			retval = translate_error(result);
		} else {
			retval = 0;
		}
	}

	return retval;
}

int nrf_inbuilt_key_read(nrf_sec_tag_t sec_tag,
			 nrf_key_mgnt_cred_type_t cred_type, uint8_t *p_buffer,
			 uint16_t *p_buffer_len)
{
	if ((p_buffer == NULL) || (p_buffer_len == NULL) ||
	    (*p_buffer_len == 0)) {
		return -EINVAL;
	}
	uint16_t scratch_buf_len = sizeof(NRF_INBUILT_KEY_OP_RD) +
				   (NRF_INBUILT_KEY_CHAR_SIZE_MAX_INT32 * 2) +
				   (NRF_INBUILT_KEY_COMMA_SIZE * 2) +
				   NRF_INBUILT_KEY_CR_CHAR_SIZE +
				   NRF_INBUILT_KEY_LF_CHAR_SIZE +
				   NRF_INBUILT_KEY_ZERO_TERMINATOR_SIZE;
	uint8_t *p_cmd = scratch_buf;

	int written = snprintf((char *)p_cmd, scratch_buf_len, "%s,%u,%u\r\n",
			       NRF_INBUILT_KEY_OP_RD, (uint32_t)sec_tag,
			       (uint8_t)cred_type);
	if ((written < 0) || (written >= *p_buffer_len)) {
		return -ENOBUFS;
	}

	bool cmee_activated = false;
	int cmee_active_result = cmee_active();

	if (cmee_active_result < 0) {
		// Could not activate CMEE.
		return -EFAULT;
	}

	if (cmee_active_result == 0) {
		cmee_set(true);
		cmee_activated = true;
	}

	enum at_cmd_state state;
	int result = at_cmd_write(scratch_buf, scratch_buf, sizeof(scratch_buf),
				  &state);
	if (cmee_activated) {
		cmee_set(false);
	}

	int retval = 0;

	if ((result != 0) && (state == AT_CMD_ERROR_CME)) {
		retval = translate_error(result);
	} else {
		retval = 0;
	}

	if (retval == 0) {
		struct at_param_list cmng_list;
		at_params_list_init(&cmng_list, 5);
		at_parser_params_from_str(scratch_buf, NULL, &cmng_list);
		size_t len;
		at_params_size_get(&cmng_list, 4, &len);
		if (len < *p_buffer) {
			at_params_list_free(&cmng_list);
			return -ENOBUFS;
		}
		at_params_string_get(&cmng_list, 4, p_buffer, &len);
		*p_buffer_len = len;
		at_params_list_free(&cmng_list);
	}

	return retval;
}

int nrf_inbuilt_key_delete(nrf_sec_tag_t sec_tag,
			   nrf_key_mgnt_cred_type_t cred_type)
{
	uint16_t scratch_buf_len = sizeof(NRF_INBUILT_KEY_OP_RM) +
				   (NRF_INBUILT_KEY_CHAR_SIZE_MAX_INT32 * 2) +
				   (NRF_INBUILT_KEY_COMMA_SIZE * 2) +
				   NRF_INBUILT_KEY_CR_CHAR_SIZE +
				   NRF_INBUILT_KEY_LF_CHAR_SIZE +
				   NRF_INBUILT_KEY_ZERO_TERMINATOR_SIZE;

#ifdef CONFIG_NRF_INBUILT_KEY_AUTHENTICATED
	// Note: The actual command is populated after the signature as this an
	// authenticate command.
	uint8_t *p_cmd = &scratch_buf[AUTHENTICATED_AT_CMD_SIGNATURE_SIZE];
	uint8_t *p_signature = scratch_buf;
#else
	uint8_t *p_cmd = &scratch_buf[0];
#endif

	int exp_len = snprintf((char *)p_cmd, scratch_buf_len, "%s,%u,%u\r\n",
			       NRF_INBUILT_KEY_OP_RM, (uint32_t)sec_tag,
			       (uint8_t)cred_type);

	if (exp_len >= scratch_buf_len) {
		return -ENOBUFS;
	}

	size_t expected_size =
		(strlen((char *)p_cmd) + NRF_INBUILT_KEY_ZERO_TERMINATOR_SIZE);

	int retval = 0;

#ifdef CONFIG_NRF_INBUILT_KEY_AUTHENTICATED
	retval = authenticated_atcmd_sign(p_cmd, expected_size, p_signature);

	expected_size +=
		AUTHENTICATED_AT_CMD_SIGNATURE_SIZE; // Include the length for
						     // the signature when
						     // writing to the AT
						     // interface.
#else
	(void)expected_size;
#endif

	if (retval == 0) {
		bool cmee_activated = false;
		int cmee_active_result = cmee_active();

		if (cmee_active_result < 0) {
			// Could not activate CMEE.
			return -EFAULT;
		}

		if (cmee_active_result == 0) {
			cmee_set(true);
			cmee_activated = true;
		}

		enum at_cmd_state state;
		int result = at_cmd_write(scratch_buf, scratch_buf,
					  scratch_buf_len, &state);
		if (cmee_activated) {
			cmee_set(false);
		}

		if ((result != 0) && (state == AT_CMD_ERROR_CME)) {
			retval = translate_error(result);
		} else {
			retval = 0;
		}
	}

	return retval;
}

int nrf_inbuilt_key_permission_set(nrf_sec_tag_t sec_tag,
				   nrf_key_mgnt_cred_type_t cred_type,
				   uint8_t perm_flags)
{
	int retval = -EOPNOTSUPP;
	return retval;
}

int nrf_inbuilt_key_exists(nrf_sec_tag_t sec_tag,
			   nrf_key_mgnt_cred_type_t cred_type, bool *p_exists,
			   uint8_t *p_perm_flags)
{
	uint16_t scratch_buf_len = sizeof(NRF_INBUILT_KEY_OP_LS) +
				   (NRF_INBUILT_KEY_CHAR_SIZE_MAX_INT32 * 2) +
				   (NRF_INBUILT_KEY_COMMA_SIZE * 2) +
				   NRF_INBUILT_KEY_CR_CHAR_SIZE +
				   NRF_INBUILT_KEY_LF_CHAR_SIZE +
				   NRF_INBUILT_KEY_ZERO_TERMINATOR_SIZE;

	uint8_t *p_cmd = &scratch_buf[0];

	int exp_len = snprintf((char *)p_cmd, scratch_buf_len, "%s,%u,%u\r\n",
			       NRF_INBUILT_KEY_OP_LS, (uint32_t)sec_tag,
			       (uint8_t)cred_type);

	if (exp_len >= scratch_buf_len) {
		return -ENOBUFS;
	}


	bool cmee_activated = false;
	int cmee_active_result = cmee_active();

	if (cmee_active_result < 0) {
		// Could not activate CMEE.
		return -EFAULT;
	}

	if (cmee_active_result == 0) {
		cmee_set(true);
		cmee_activated = true;
	}

	enum at_cmd_state state;
	int result = at_cmd_write(scratch_buf, scratch_buf, sizeof(scratch_buf),
				  &state);
	if (cmee_activated) {
		cmee_set(false);
	}

	int retval = 0;
	if ((result != 0) && (state == AT_CMD_ERROR_CME)) {
		retval = translate_error(result);
	}

	if ((retval == 0) && (strlen(scratch_buf) > 0)) {
		*p_exists = true;
		*p_perm_flags = 0;
	} else {
		retval = 0;
		*p_exists = false;
	}

	return retval;
}
