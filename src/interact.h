#ifndef INTERACT_H_
#define INTERACT_H_

#include "constants.h"

void interact_prompt_user(const char * prompt, char * response, size_t length);
void interact_print_percent_done(uint32_t percent);

#endif /* INTERACT_H_ */
