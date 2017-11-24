/*
 * The runner function for BuseLFS
 *
 * @author Bernard Dickens
 */

#include "buselfs.h"

int main(int argc, char * argv[])
{
    int ret = -1;
    volatile CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;

    Try
    {
        ret = buselfs_main(argc, argv);
    }

    Catch(e)
    {
        CEXCEPTION_NO_CATCH_HANDLER(e);
    }

    return ret;
}
