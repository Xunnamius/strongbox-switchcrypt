#include <limits.h>
#include <string.h>

#include "unity.h"
#include "bitmask.h"

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

#define BITMASK_BYTE_LENGTH 4 // 32 bits
static bitmask_t * bitmask;

void setUp(void)
{
    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);

    bitmask = bitmask_init(NULL, BITMASK_BYTE_LENGTH);
}

void tearDown(void)
{
    zlog_fini();
    bitmask_fini(bitmask);
}

void test_bitmask_init_should_initialize_bitmask(void)
{
    TEST_ASSERT_NOT_NULL(bitmask);
    TEST_ASSERT_EQUAL_UINT(BITMASK_BYTE_LENGTH, bitmask->byte_length);

    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = "";
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_init_should_throw_exception_on_bad_byte_length(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_SIZE_T_OUT_OF_BOUNDS;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(bitmask = bitmask_init(NULL, 0));
}

void test_bitmask_fini_works_as_expected(void)
{
    bitmask_fini(bitmask);

    uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    bitmask = bitmask_init(data, sizeof data);
    
    // XXX: The below is called by tearDown()
    //bitmask_fini(bitmask);
}

void test_bitmask_functions_throw_exception_on_out_of_bounds_indices(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_OUT_OF_BOUNDS;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    unsigned int out_of_bounds = BITMASK_BYTE_LENGTH * 8;

    TRY_FN_CATCH_EXCEPTION(bitmask_set_bit(bitmask, out_of_bounds));
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bit(bitmask, out_of_bounds));
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bit(bitmask, out_of_bounds));

    TRY_FN_CATCH_EXCEPTION(bitmask_set_bits(bitmask, out_of_bounds, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_set_bits(bitmask, 0, out_of_bounds + 1));

    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bits(bitmask, out_of_bounds, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bits(bitmask, 0, out_of_bounds + 1));

    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bits(bitmask, out_of_bounds, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bits(bitmask, 0, out_of_bounds + 1));

    TRY_FN_CATCH_EXCEPTION(bitmask_is_bit_set(bitmask, out_of_bounds));

    TRY_FN_CATCH_EXCEPTION(bitmask_are_bits_set(bitmask, out_of_bounds, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_are_bits_set(bitmask, 0, out_of_bounds + 1));
}

void test_bitmask_is_and_set_bit_should_set_and_check_the_nth_bit(void)
{
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));
    bitmask_set_bit(bitmask, 0);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 0));
    bitmask_set_bit(bitmask, 0);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 0));

    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 31));
    bitmask_set_bit(bitmask, 31);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 31));
    bitmask_set_bit(bitmask, 31);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 31));
}

void test_bitmask_clear_bit_should_clear_the_nth_bit(void)
{
    bitmask_set_bit(bitmask, 0);
    bitmask_clear_bit(bitmask, 0);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));
    bitmask_clear_bit(bitmask, 0);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));

    bitmask_set_bit(bitmask, 31);
    bitmask_clear_bit(bitmask, 31);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 31));
    bitmask_clear_bit(bitmask, 31);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 31));
}

void test_bitmask_toggle_bit_should_toggle_the_nth_bit(void)
{
    bitmask_set_bit(bitmask, 0);
    bitmask_toggle_bit(bitmask, 0);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));
    bitmask_toggle_bit(bitmask, 0);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 0));
    bitmask_toggle_bit(bitmask, 0);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));

    bitmask_toggle_bit(bitmask, 31);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 31));
    bitmask_toggle_bit(bitmask, 31);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 31));
    bitmask_toggle_bit(bitmask, 31);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 31));
}

void test_bitmask_length_accepting_functions_do_not_throw_exception_on_in_bounds_edge_cases(void)
{
    // No errors thrown?!
    bitmask_set_bits(bitmask, 0, 0);
    bitmask_clear_bits(bitmask, 0, 0);
    bitmask_toggle_bits(bitmask, 0, 0);
    (void) bitmask_are_bits_set(bitmask, 0, 0);

    bitmask_set_bits(bitmask, 0, 32);
    bitmask_clear_bits(bitmask, 0, 32);
    bitmask_toggle_bits(bitmask, 0, 32);
    (void) bitmask_are_bits_set(bitmask, 0, 32);
}

void test_bitmask_set_mask_sets_mask_to_all_1s(void)
{
    unsigned char expected_mask_1s[BITMASK_BYTE_LENGTH] = { 0xFF, 0xFF, 0xFF, 0xFF };

    bitmask_set_mask(bitmask);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask_1s, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_clear_mask_sets_mask_to_all_0s(void)
{
    unsigned char expected_mask_0s[BITMASK_BYTE_LENGTH] = { 0x00, 0x00, 0x00, 0x00 };

    bitmask_clear_mask(bitmask);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask_0s, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_length_accepting_functions_do_not_mutate_mask_on_0_length_parameter(void)
{
    unsigned char expected_mask_0s[BITMASK_BYTE_LENGTH] = { 0x00, 0x00, 0x00, 0x00 };
    unsigned char expected_mask_1s[BITMASK_BYTE_LENGTH] = { 0xFF, 0xFF, 0xFF, 0xFF };

    bitmask_clear_mask(bitmask);
    bitmask_set_bits(bitmask, 0, 0);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask_0s, bitmask->mask, BITMASK_BYTE_LENGTH);
    bitmask_set_mask(bitmask);
    bitmask_clear_bits(bitmask, 0, 0);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask_1s, bitmask->mask, BITMASK_BYTE_LENGTH);
    bitmask_toggle_bits(bitmask, 0, 0);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask_1s, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_set_bits_sets_expected_bits(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0x81, 0x80, 0xFF, 0x01 };

    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));
    bitmask_set_bits(bitmask, 0, 1);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 0));
    bitmask_set_bits(bitmask, 7, 1);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 7));

    bitmask_set_bits(bitmask, 8, 1);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 8));
    bitmask_set_bits(bitmask, 31, 1);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 31));

    bitmask_set_bits(bitmask, 16, 8);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_set_bits_sets_all_bits_when_length_32(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0xFF, 0xFF, 0xFF, 0xFF };

    bitmask_set_bits(bitmask, 0, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_set_bits_sets_bits_across_chars_properly(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0x07, 0xFF, 0xFF, 0xF0 };

    bitmask_set_bits(bitmask, 5, 23);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_clear_bits_clears_expected_bits(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0x7E, 0x7F, 0x00, 0xFE };
    bitmask_set_mask(bitmask);

    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 0));
    bitmask_clear_bits(bitmask, 0, 1);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));
    bitmask_clear_bits(bitmask, 7, 1);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 7));

    bitmask_clear_bits(bitmask, 8, 1);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 8));
    bitmask_clear_bits(bitmask, 31, 1);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 31));

    bitmask_clear_bits(bitmask, 16, 8);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_clear_bits_clears_all_bits_when_length_32(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0x00, 0x00, 0x00, 0x00 };
    bitmask_set_mask(bitmask);

    bitmask_clear_bits(bitmask, 0, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_clear_bits_clears_bits_across_chars_properly(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0xF8, 0x00, 0x00, 0x0F };
    bitmask_set_mask(bitmask);

    bitmask_clear_bits(bitmask, 5, 23);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_toggle_bits_toggles_expected_bits(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0x79, 0x80, 0xFF, 0x0E };
    bitmask_set_bits(bitmask, 0, 5);
    bitmask_set_bits(bitmask, 28, 4);

    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 0));
    bitmask_toggle_bits(bitmask, 0, 1);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 0));
    bitmask_toggle_bits(bitmask, 7, 1);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 7));

    bitmask_toggle_bits(bitmask, 8, 1);
    TEST_ASSERT_EQUAL_INT(1, bitmask_is_bit_set(bitmask, 8));
    bitmask_toggle_bits(bitmask, 31, 1);
    TEST_ASSERT_EQUAL_INT(0, bitmask_is_bit_set(bitmask, 31));

    bitmask_toggle_bits(bitmask, 16, 8);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_toggle_bits_toggles_all_bits_when_length_32(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0x07, 0xFF, 0xFF, 0xF0 };
    bitmask_set_bits(bitmask, 0, 5);
    bitmask_set_bits(bitmask, 28, 4);

    bitmask_toggle_bits(bitmask, 0, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_toggle_bits_toggles_bits_across_chars_properly(void)
{
    unsigned char expected_mask[BITMASK_BYTE_LENGTH] = { 0xF8, 0x00, 0x00, 0x0F };
    bitmask_set_mask(bitmask);

    bitmask_toggle_bits(bitmask, 5, 23);
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_are_bits_set_checks_expected_bits(void)
{
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 0, 5));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 28, 4));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 16, 8));

    bitmask_set_bits(bitmask, 0, 5);
    bitmask_set_bits(bitmask, 28, 4);

    TEST_ASSERT_EQUAL_INT(1, bitmask_are_bits_set(bitmask, 0, 5));
    TEST_ASSERT_EQUAL_INT(1, bitmask_are_bits_set(bitmask, 28, 4));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 16, 8));
}

void test_bitmask_are_bits_set_checks_all_bits_when_length_32(void)
{
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 0, 32));
    bitmask_set_mask(bitmask);
    TEST_ASSERT_EQUAL_INT(1, bitmask_are_bits_set(bitmask, 0, 32));
}

void test_bitmask_are_bits_set_checks_bits_across_chars_properly(void)
{
    bitmask_set_bits(bitmask, 0, 5);

    TEST_ASSERT_EQUAL_INT(1, bitmask_are_bits_set(bitmask, 0, 4));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 0, 6));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 0, 16));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 0, 32));
}

void test_bitmask_are_bits_set_returns_0_on_0_length_parameter(void)
{
    bitmask_set_mask(bitmask);
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 0, 0));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 11, 0));
    TEST_ASSERT_EQUAL_INT(0, bitmask_are_bits_set(bitmask, 31, 0));
}

void test_bitmask_any_bits_set_checks_expected_bits(void)
{
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 0, 1));
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 0, 5));
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 28, 4));
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 16, 8));

    bitmask_set_bits(bitmask, 4, 6);
    bitmask_set_bits(bitmask, 28, 4);

    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 0, 5));
    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 5, 1));
    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 5, 27));
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 10, 18));
    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 10, 19));
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 0, 1));
}

void test_bitmask_any_bits_set_checks_expected_bits2(void)
{
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 0, 1));

    bitmask_set_bits(bitmask, 0, 4);

    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 4, 1));
}

void test_bitmask_any_bits_set_checks_all_bits_when_length_32(void)
{
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 0, 32));
    bitmask_set_mask(bitmask);
    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 0, 32));

}

void test_bitmask_any_bits_set_checks_bits_across_chars_properly(void)
{
    bitmask_set_bits(bitmask, 0, 5);

    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 0, 4));
    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 0, 6));
    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 0, 16));
    TEST_ASSERT_EQUAL_INT(1, bitmask_any_bits_set(bitmask, 0, 32));
}

void test_bitmask_any_bits_set_returns_0_on_0_length_parameter(void)
{
    bitmask_set_mask(bitmask);
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 0, 0));
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 11, 0));
    TEST_ASSERT_EQUAL_INT(0, bitmask_any_bits_set(bitmask, 31, 0));
}
