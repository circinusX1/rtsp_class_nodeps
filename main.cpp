#include <iostream>
#include <string.h>
#include "rtsp_class.h"

bool __debug = 0;
#define TO_RENDER  28000

//////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Tested with rtsp digoo cam
/// \param Tested with R-PI r4vtrspserver
int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);
    if(argc < 2)
    {
        std::cout << argv[0] << " rtsp://IP/stream <user:password>\n";
        return -1;
    }
    std::string url = argv[1];
    std::string cred;
    rtsp_class  rtsp;
    frame_load  output;
    pipiefile   pipe("/tmp/movie_pipe.mov");

    if(argc==3){
        cred = argv[2];
    }
    __debug = false;

    if(pipe.ok())
    {
        bool okay = true;
        if(rtsp.cmd_play(url, cred))
        {
            std::cout << "From another terminal run: ffplay /tmp/movie_pipie.mov, and wait...\n";
            sleep(3);
            while(okay)
            {
                okay = rtsp.spin(output);
                if(output.is_ready() && output.length()>TO_RENDER)
                {
                    std::cout << "piping "<< output.length() << " octets\n";
                    pipe.stream(output.buffer(),output.length());
                    output.reset();
                }
                ::usleep(10000);
            }
        }
    }
    else
    {
        std::cout << "cannot create pipe /tmp/movie.mov\n";
    }
    return 0;
}
