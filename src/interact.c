/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "interact.h"
#include "constants.h"

#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>

void interact_prompt_user(const char * prompt, char * response, size_t length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    struct termios term, term_orig;
    tcgetattr(STDIN_FILENO, &term);
    term_orig = term;
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);

    char * r;

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-result"

    printf("%s", prompt);
    scanf("%ms", &r);
    printf("\n");

    #pragma GCC diagnostic pop 

    IFDEBUG(dzlog_debug("prompt = %s", prompt));
    IFDEBUG(dzlog_debug("r = %s", r));

    memcpy(response, r, MIN(length, strlen(r) + 1));
    free(r);

    IFDEBUG(dzlog_debug("response = %s", response));

    /* Remember to set back, or your commands won't echo! */
    tcsetattr(STDIN_FILENO, TCSANOW, &term_orig);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

// Expects an initial printf of the form: printf("whateveryouwanthere: 0%%")
static uint32_t previous_percent = 0;

void interact_print_percent_done(uint32_t percent)
{
    if(!percent || ((percent - 1) / 10 == 0 && previous_percent < 10))
        printf("\b\b");
    else
        printf("\b\b\b");

    previous_percent = percent;
    printf("%i%%", (int) percent);
    fflush(stdout);
}
