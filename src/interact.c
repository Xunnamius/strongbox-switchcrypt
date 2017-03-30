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

    printf("%s", prompt);
    scanf("%ms", &r);
    printf("\n");

    IFDEBUG(dzlog_debug("prompt = %s", prompt));
    IFDEBUG(dzlog_debug("r = %s", r));

    memcpy(response, r, MIN(length, strlen(r) + 1));
    free(r);

    IFDEBUG(dzlog_debug("response = %s", response));

    /* Remember to set back, or your commands won't echo! */
    tcsetattr(STDIN_FILENO, TCSANOW, &term_orig);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
