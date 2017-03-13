/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include "interact.h"

void interact_prompt_user(const char * prompt, char * response)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    struct termios term, term_orig;
    tcgetattr(STDIN_FILENO, &term);
    term_orig = term;
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);

    printf("%s", prompt);
    scanf("%s", response);

    /* Remember to set back, or your commands won't echo! */
    tcsetattr(STDIN_FILENO, TCSANOW, &term_orig);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
