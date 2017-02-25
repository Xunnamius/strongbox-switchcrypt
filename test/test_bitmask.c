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
    TEST_ASSERT_EQUAL_INT(e_expected, e_actual);

#define BITMASK_BYTE_LENGTH 4 // 32 bits
static bitmask_t * bitmask;

void setUp(void)
{
    bitmask = bitmask_init(BITMASK_BYTE_LENGTH);
}

void tearDown(void)
{
    bitmask_fini(bitmask);
}

void test_bitmask_init_should_initialize_bitmask(void)
{
    TEST_ASSERT_NOT_NULL(bitmask);
    TEST_ASSERT_EQUAL_UINT(BITMASK_BYTE_LENGTH, bitmask->byte_length);

    char expected_mask[BITMASK_BYTE_LENGTH] = "";
    TEST_ASSERT_EQUAL_MEMORY(expected_mask, bitmask->mask, BITMASK_BYTE_LENGTH);
}

void test_bitmask_functions_throw_exception_on_out_of_bounds_indices(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_OUT_OF_BOUNDS;
    CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(bitmask_set_bit(bitmask, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_set_bit(bitmask, 32));
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bit(bitmask, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bit(bitmask, 32));
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bit(bitmask, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bit(bitmask, 32));

    e_expected = EXCEPTION_NO_EXCEPTION;
    TRY_FN_CATCH_EXCEPTION(bitmask_set_bits(bitmask, 0, 0));
    e_expected = EXCEPTION_OUT_OF_BOUNDS;
    TRY_FN_CATCH_EXCEPTION(bitmask_set_bits(bitmask, 0, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_set_bits(bitmask, -1, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_set_bits(bitmask, 32, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_set_bits(bitmask, 0, 32));

    e_expected = EXCEPTION_NO_EXCEPTION;
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bits(bitmask, 0, 0));
    e_expected = EXCEPTION_OUT_OF_BOUNDS;
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bits(bitmask, 0, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bits(bitmask, -1, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bits(bitmask, 32, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_clear_bits(bitmask, 0, 32));

    e_expected = EXCEPTION_NO_EXCEPTION;
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bits(bitmask, 0, 0));
    e_expected = EXCEPTION_OUT_OF_BOUNDS;
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bits(bitmask, 0, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bits(bitmask, -1, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bits(bitmask, 32, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_toggle_bits(bitmask, 0, 32));

    TRY_FN_CATCH_EXCEPTION(bitmask_is_bit_set(bitmask, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_is_bit_set(bitmask, 32));

    e_expected = EXCEPTION_NO_EXCEPTION;
    TRY_FN_CATCH_EXCEPTION(bitmask_are_bits_set(bitmask, 0, 0));
    e_expected = EXCEPTION_OUT_OF_BOUNDS;
    TRY_FN_CATCH_EXCEPTION(bitmask_are_bits_set(bitmask, 0, -1));
    TRY_FN_CATCH_EXCEPTION(bitmask_are_bits_set(bitmask, -1, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_are_bits_set(bitmask, 32, 0));
    TRY_FN_CATCH_EXCEPTION(bitmask_are_bits_set(bitmask, 0, 32));
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
