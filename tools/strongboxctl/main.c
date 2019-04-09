#include "strongbox.h"

#include <assert.h>

void print_help_text_and_bail(char * program)
{
    printf(
        "\nUsage:\n"
        "  %s info  message_queue_name\n\n"
        "  %s read  message_queue_name number_of_messages\n\n"
        "  %s write message_queue_name message_opcode [message_payload]\n\n"

        "::info command::\n"
        "This command will return useful information about a queue, including if it exists or not.\n\n"
        "Example: %s info /incoming.message.queue\n\n"

        "::read command::\n"
        "This command will dequeue and return the specified number of messages from the specified queue. This command\n"
        " will not error if more messages are requested than are messages in the queue.\n\n"
        "Example: %s read /somequeue 5\n\n"

        "::write command::\n"
        "This command will enqueue a new message into the specified queue. If the queue is full, this command will\n"
        " terminate in error. Note the following constraints:\n"
        "   - 0 < `message_opcode` <= 255\n"
        "   - 0 <= byte length of message_payload <  %u (i.e. this can be an empty string/omitted entirely)\n\n"
        "Example: %s write /somequeue 4 payloadhere\n"
        "Example: %s write /somequeue 40 'some data required by this command'\n"
        "Example: %s write /somequeue 250\n\n"

        "See README.md and constants.h for more details. Don't forget to run as root and mount /dev/mq!\n\n",
        program, program, program, program, program, BLFS_SV_MESSAGE_SIZE_BYTES, program, program, program);

        Throw(EXCEPTION_MUST_HALT);
}

int sbctl_main(int argc, char * argv[])
{
    IFDEBUG3(printf("<bare debug>: >>>> entering %s\n", __func__));

    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s", "sbctl_level", STRINGIZE(BLFS_DEBUG_LEVEL));

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);

    IFDEBUG(dzlog_debug("<switched to zlog for logging>"));

    buselfs_state_t buselfs_state;

    IFDEBUG(dzlog_debug("Interpreting and executing command..."));
    IFDEBUG(dzlog_debug("argc: %i", argc));

    if(argc <= 1 || argc > 5)
        print_help_text_and_bail(argv[0]);

    char * cin_cmd = argv[1];
    char * cin_qname;
    uint32_t cin_msg_count;
    uint8_t cin_opcode;
    uint8_t cin_payload[BLFS_SV_MESSAGE_SIZE_BYTES - 1] = { 0 };
    blfs_mq_msg_t msg;

    IFDEBUG(dzlog_debug("cin_cmd: %s", cin_cmd));

    if(strcmp(cin_cmd, "info") == 0)
    {
        if(argc != 3)
            print_help_text_and_bail(argv[0]);

        else
        {
            cin_qname = argv[2];

            IFDEBUG(dzlog_debug("cin_qname: %s", cin_qname));
        }

        dzlog_notice("(not implemented)");
    }

    else if(strcmp(cin_cmd, "read") == 0)
    {
        if(argc != 4)
            print_help_text_and_bail(argv[0]);

        else
        {
            cin_qname = argv[2];

            int64_t cin_msg_count_int = strtoll(argv[3], NULL, 0);
            cin_msg_count = (uint32_t) cin_msg_count_int;

            if(cin_msg_count_int != cin_msg_count)
                Throw(EXCEPTION_SIZE_T_OUT_OF_BOUNDS);

            IFDEBUG(dzlog_debug("cin_qname: %s", cin_qname));
            IFDEBUG(dzlog_debug("cin_msg_count: %u", cin_msg_count));

            buselfs_state.qd_incoming = blfs_open_queue(cin_qname, 0);


            while(cin_msg_count--)
            {
                blfs_read_input_queue(&buselfs_state, &msg);

                if(!msg.opcode)
                {
                    printf("(no more messages in queue)\n");
                    break;
                }

                printf("::Message::\n\n"
                       "Priority: 0\n"
                       "Opcode:   %u\n\n"
                       ":Payload:\n\n",
                    msg.opcode);

                for(size_t i = 0; i < sizeof msg.payload; ++i)
                    printf((i + 1) % 15 == 0 ? "0x%02hhx\n" : "0x%02hhx ", msg.payload[i]);

                printf("\n---\n\n");
            }
        }
    }

    else if(strcmp(cin_cmd, "write") == 0)
    {
        if(argc != 4 && argc != 5)
            print_help_text_and_bail(argv[0]);

        else
        {
            cin_qname = argv[2];

            int64_t cin_opcode_int = strtoll(argv[3], NULL, 0);
            cin_opcode = (uint8_t) cin_opcode_int;

            if(cin_opcode_int != cin_opcode)
                Throw(EXCEPTION_SIZE_T_OUT_OF_BOUNDS);

            if(argc == 5)
            {
                size_t argv4_len = strlen(argv[4]) - 1; // ? -1 to account for null char

                IFDEBUG(dzlog_debug("(argv4_len: %zu)", argv4_len));

                if(argv4_len > sizeof cin_payload)
                {
                    dzlog_fatal(
                        "Length of supplied payload (%zu) must be less than or equal to %zu",
                        argv4_len,
                        sizeof cin_payload
                    );

                    Throw(EXCEPTION_BAD_ARGUMENT_FORM);
                }

                memcpy(cin_payload, argv[4], argv4_len);
            }

            IFDEBUG(dzlog_debug("cin_qname: %s", cin_qname));
            IFDEBUG(dzlog_debug("cin_opcode: %u", cin_opcode));
            IFDEBUG(dzlog_debug("cin_payload: "));

            if(argc == 5)
                IFDEBUG(hdzlog_debug(cin_payload, sizeof cin_payload));
            else
                IFDEBUG(dzlog_debug("(not given)"));

            assert(sizeof msg.payload == sizeof cin_payload);
            memcpy(msg.payload, cin_payload, sizeof msg.payload);

            msg.opcode = cin_opcode;

            buselfs_state.qd_outgoing = blfs_open_queue(cin_qname, 1);
            blfs_write_output_queue(&buselfs_state, &msg, 0);

            printf("Write was successful!\n");
        }
    }

    else
        print_help_text_and_bail(argv[0]);

    IFDEBUG3(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

int main(int argc, char * argv[])
{
    int ret = -1;
    volatile CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;

    Try
    {
        ret = sbctl_main(argc, argv);
    }

    Catch(e)
    {
        CEXCEPTION_NO_CATCH_HANDLER(e);
    }

    return ret;
}
