/***************************************************************************************************
 * By O. Marius Chincisan.
 * No License
 *
 *  Pulled together from simplertsp.cpp and linux exanples rtp.c
 *
 *
 ************************************************************************************************/

#ifndef RTSP_CLASS
#define RTSP_CLASS

#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <sys/select.h>
#include <netdb.h>
#include <iostream>
#include <vector>
#include <list>
#include <map>
#include "replace_with_yours.h"

///////////////////////////////////////////////////////////////////////////////////////////////////
#define CHECK_BIT(var, pos) !!((var) & (1 << (pos)))
#define PACK_ALIGN_1   __attribute__((packed, aligned(1)))

///////////////////////////////////////////////////////////////////////////////////////////////////
constexpr int TIO_RD      = 0x1;
constexpr int TIO_WR      = 0x2;
constexpr int TIO_ER      = 0x4;
constexpr int UIO_RD      = 0x8;
constexpr int UIO_WR      = 0x10;
constexpr int UIO_ER      = 0x20;
constexpr int USIO_RD     = 0x40;
constexpr int USIO_WR     = 0x80;
constexpr int USIO_ER     = 0x100;
constexpr int TRACK_ID    = 0;

///////////////////////////////////////////////////////////////////////////////////////////////////
enum {
    NAL_TYPE_UNDEFINED = 0,
    NAL_TYPE_SINGLE_NAL_MIN	= 1,
    NAL_TYPE_SINGLE_NAL_MAX	= 23,
    NAL_TYPE_STAP_A		= 24,
    NAL_TYPE_FU_A		= 28,
};

///////////////////////////////////////////////////////////////////////////////////////////////////
enum RtspPlayerState {
    RtspSendOptions = 0,
    RtspHandleOptions,
    RtspSendDescribe,
    RtspHandleDescribe,
    RtspSendVideoSetup,
    RtspHandleVideoSetup,
    RtspSendAudioSetup,
    RtspHandleAudioSetup,
    RtspSendPlay,
    RtspHandlePlay,
    RtspSendPause,
    RtspHandlePause,
    RtspSendTerminate,
    RtspHandleTerminate,
    RtspIdle,
    RtspTurnOff,
};

///////////////////////////////////////////////////////////////////////////////////////////////////
enum RtspPlayerCSeq {
    RTSPOPTIONS = 1,
    RTSPDESCRIBE,
    RTSPVIDEO_SETUP,
    RTSPAUDIO_SETUP,
    RTSPPLAY,
    RTSPPAUSE,
    RTSPTEARDOWN,
};

///////////////////////////////////////////////////////////////////////////////////////////////////
struct rtp_header {
    int version:2;     /* protocol version */
    int padding:1;     /* padding flag */
    int extension:1;   /* header extension flag */
    int cc:4;          /* CSRC count */
    int marker:1;      /* marker bit */
    int pt:7;          /* payload type */
    uint16_t seq:16;            /* sequence number */
    uint32_t ts;                /* timestamp */
    uint32_t ssrc;              /* synchronization source */
    uint32_t csrc[1];           /* optional CSRC list */
}PACK_ALIGN_1;

///////////////////////////////////////////////////////////////////////////////////////////////////
struct rtp_stats {
    uint16_t first_seq;         /* first sequence                   */
    uint16_t highest_seq;       /* highest sequence                 */
    uint16_t rtp_received;      /* RTP sequence number received     */
    uint32_t rtp_identifier;    /* source identifier                */
    uint32_t rtp_ts;            /* RTP timestamp                    */
    uint32_t rtp_cum_lost;       /* RTP cumulative packet lost       */
    uint32_t rtp_expected_prior;/* RTP expected prior               */
    uint32_t rtp_received_prior;/* RTP received prior               */
    uint32_t transit;           /* Transit time. RFC3550 A.8        */
    uint32_t jitter;            /* Jitter                           */
    uint32_t lst;
    uint32_t last_dlsr;         /* Last DLSR                        */
    uint32_t last_rcv_SR_ts;    /* Last arrival in RTP format       */
    uint32_t delay_snc_last_SR; /* Delay sinde last SR              */
    struct timeval
            last_rcv_SR_time;           /* Last SR arrival                  */
    struct timeval
            last_rcv_time;
    double rtt_frac;
};

///////////////////////////////////////////////////////////////////////////////////////////////////
class frame_load;           // replace this with your frames eater.

///////////////////////////////////////////////////////////////////////////////////////////////////
class rtsp_class
{
public:
    rtsp_class();
    ~rtsp_class();
    bool cmd_play(std::string url, const std::string& user);
    bool spin(frame_load& pf);
    void stop();

protected:
    bool _mess_response(const char* , size_t bufsize);
    void  _do_udp(const uint8_t* buf, size_t bufsize, frame_load& pf);
    bool _spawn_udp();
    bool _authenticate();
    void _seed();
    int  _harvest();
    bool _create_udp(int port, int);
    void _reset();
    void _send_request();
    void _rtp_stats_print();
    void _rtp_stats_update(struct rtp_header *rtp_h);
    int  _write_nal(frame_load& pf);
    int  _write_afternal(const void *buf, size_t count, frame_load& pf, bool done=false);
    int  _rtp_parse(unsigned char *raw, int size, frame_load& pf);

private:
    int                                 _sequence = 0;
    int                                 _waitseq = 0;
    std::string                         _auth_hdr;
    std::map<std::string, std::string>   _sdps;
    std::map<std::string, std::string>   _hdrs;
    std::list<std::string>               _query;
    bool                                 _request_sent = false;
    std::string                          _rtspurl;
    int                                  _client_ports[2] = {15392,15393};
    int                                  _server_ports[2] = {0,0};
    std::string                          _uri;
    std::string                          _host;
    std::string                          _credentials;
    std::string                          _session;
    std::string                          _request;
    int                                  _dims[2];
    tcp_cli_sock                         _tcp;
    udp_sock                             _udp;
    udp_sock                             _udpc;
    fd_set                               _readfd;
    fd_set                               _writefd;
    fd_set                               _errorfd;
    int                                  _maxfd = 0;
    rtp_stats                            _rtp_st;
    uint8_t*                             _recvbuf = nullptr;
};

#endif /* RtspPlayer_hpp */
