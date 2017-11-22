#include <string.h>

#include "unity.h"
#include "vector.h"

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

static vector_t * vector;

void setUp(void)
{
    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);

    vector = vector_init();
}

void tearDown(void)
{
    zlog_fini();
    vector_fini(vector);
}

void test_vector_functions_throw_exceptions_as_expected(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_OUT_OF_BOUNDS;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(vector_delete(vector, 0));
    TRY_FN_CATCH_EXCEPTION(vector_get(vector, 0));
    TRY_FN_CATCH_EXCEPTION(vector_set(vector, 0, 0));

    TRY_FN_CATCH_EXCEPTION(vector_delete(vector, 1));
    TRY_FN_CATCH_EXCEPTION(vector_get(vector, 1));
    TRY_FN_CATCH_EXCEPTION(vector_set(vector, 1, (int *) 1));

    TEST_ASSERT_EQUAL_INT(0, vector->count);
}

void test_vector_add_and_get_perform_as_expected(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_OUT_OF_BOUNDS;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    int i_expected = 5;
    int j_expected = 15;

    vector_add(vector, &i_expected);
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 0));
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 0));
    TRY_FN_CATCH_EXCEPTION(vector_get(vector, 1));

    vector_add(vector, &i_expected);
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 1));
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 1));
    TRY_FN_CATCH_EXCEPTION(vector_get(vector, 2));

    vector_add(vector, &j_expected);

    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 0));
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 1));
    TEST_ASSERT_EQUAL_INT(j_expected, *(int *) vector_get(vector, 2));

    TEST_ASSERT_EQUAL_INT(3, vector->count);
}

void test_vector_delete_removes_element_as_expected(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_OUT_OF_BOUNDS;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    int i_expected = 5;
    int j_expected = -55;
    int k_expected = 555;

    vector_add(vector, &i_expected);
    vector_delete(vector, 0);
    TRY_FN_CATCH_EXCEPTION(vector_get(vector, 0));
    TRY_FN_CATCH_EXCEPTION(vector_get(vector, 1));
    TEST_ASSERT_EQUAL_INT(0, vector->count);

    vector_add(vector, &i_expected);
    vector_add(vector, &j_expected);
    vector_add(vector, &k_expected);

    vector_delete(vector, 0);

    TRY_FN_CATCH_EXCEPTION(vector_get(vector, 2));

    TEST_ASSERT_EQUAL_INT(j_expected, *(int *) vector_get(vector, 0));
    TEST_ASSERT_EQUAL_INT(k_expected, *(int *) vector_get(vector, 1));
}


void test_vector_set_sets_element_as_expected(void)
{
    int i_expected = 5;
    int set_expected = -5;

    vector_add(vector, &i_expected);
    vector_add(vector, &i_expected);
    vector_add(vector, &i_expected);

    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 1));
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 2));

    vector_set(vector, 1, &set_expected);

    TEST_ASSERT_EQUAL_INT(set_expected, *(int *) vector_get(vector, 1));
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 0));
    TEST_ASSERT_EQUAL_INT(i_expected, *(int *) vector_get(vector, 2));
}

void test_vector_add_grows_array_size_as_expected(void)
{
    int i_expected = 5;
    int j_expected = -55;
    int k_expected = 555;

    for(size_t i = 0; i < 50; ++i)
    {
        vector_add(vector, &i_expected);
        vector_add(vector, &j_expected);
        vector_add(vector, &k_expected);
    }

    TEST_ASSERT_EQUAL_INT(150, vector->count);
    TEST_ASSERT_EQUAL_INT(160, vector->size); // XXX: Assuming 2x growth factor
}
