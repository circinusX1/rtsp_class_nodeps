/***************************************************************************************************
 * By O. Marius Chincisan.
 * No License
 *
 *  Pulled together from simple-rtsp.cpp and linux examples rtp.c
 *
 *
 **************************************************************************************************/
#include <string.h>
#include <sstream>
#include "rtsp_class.h"
#include <sys/time.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
static constexpr size_t      CHUNK_LEN     (1024*4);
static constexpr const char* USR_AGENT =   "lili-1.0";
static constexpr const char* WWW_AUTH  =   "WWW-Authenticate: ";
static constexpr const char* ACCEPT    =   "Accept: ";
static constexpr const char* CONT_TYPE =   "Content-Type: ";
static constexpr const char* CONT_LEN  =   "Content-Length: ";
static constexpr const char* CONT_BASE =   "Content-Base: ";
static constexpr const char* TRANSPORT =   "Transport: ";
static constexpr const char* HDR_ABASIC = "Authorization: Basic ";
static constexpr const char* CSEQ      =   "CSeq: ";
static constexpr const char* CLI_PORT  =   "client_port=";
static constexpr const char* SRV_PORT  =   "server_port=";
static constexpr const char* SESSION   =   "Session: ";
static constexpr const char*  SDP_ATYPE =   "a=type:";
static constexpr const char*  SDP_ACTL  =   "a=control:";
static constexpr const char*  SDP_M     =   "m=";
static constexpr const char*  SDP_ARMAP =   "a=rtpmap:";
static constexpr const char*  SDP_FMT   =   "a=fmtp:";
static constexpr const char*  SDP_XDIM  =   "a=x-dimensions:";

////////////////////////////////////////////////////////////////////////////////////////////////////
constexpr const char* __hdrs[] = {
    ACCEPT,
    WWW_AUTH,
    CONT_TYPE,
    CONT_LEN,
    CONT_BASE,
    TRANSPORT,
    CLI_PORT,
    SRV_PORT,
    SESSION,
    nullptr
};

////////////////////////////////////////////////////////////////////////////////////////////////////
constexpr const char* __sdps[] = {
    SDP_ATYPE,
    SDP_ACTL,
    SDP_M,
    SDP_ARMAP,
    SDP_FMT,
    SDP_XDIM,
    nullptr
};

////////////////////////////////////////////////////////////////////////////////////////////////////
extern bool __debug;
static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
static int parseURL(const char* url, char* scheme, size_t
                    maxSchemeLen, char* host, size_t maxHostLen,
                    int* port, char* path, size_t maxPathLen);

////////////////////////////////////////////////////////////////////////////////////////////////////
rtsp_class::rtsp_class() {
    _recvbuf = new uint8_t[CHUNK_LEN];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
rtsp_class::~rtsp_class() {
    delete[] _recvbuf;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void  rtsp_class::_reset()
{
    _query.clear();
    _query.push_back("OPTIONS");
    _query.push_back("DESCRIBE");
    _query.push_back("SETUP");
    _query.push_back("PLAY");
    _sequence = 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void rtsp_class::_send_request()
{
    if(_query.size() && _request_sent==false)
    {
        std::string request;
        const std::string& what = _query.front();
        _waitseq = _sequence;
        request += what;
        request += " ";

        if(_hdrs.find(CONT_BASE)!=_hdrs.end())
        {
            request += _hdrs[CONT_BASE];
        }
        else if(_sdps.find(SDP_ACTL)!=_sdps.end())
        {
            request += _sdps[SDP_ACTL];
        }
        else
        {
            request += _rtspurl;
        }

        request += " RTSP/1.0\r\n";
        request += "CSeq: "; request += std::to_string(_sequence); request+="\r\n";
        if(!_auth_hdr.empty())
        {
            request += _auth_hdr;
        }
        if(what == "DESCRIBE")
        {
            request += "Accept: application/sdp\r\n";
        }
        else if(what == "SETUP")
        {
            request += "Transport: RTP/AVP/UDP;unicast;client_port=";
            request += std::to_string(_client_ports[0]);
            request += "-";
            request += std::to_string(_client_ports[1]);
            request += "\r\n";
        }
        else if(what == "PLAY")
        {
            request += SESSION;
            request += _hdrs[SESSION];
            request += "\r\n";
            request += "Range: npt=0.000-\r\n";
        }
        request += USR_AGENT; request +="\r\n\r\n";
        _sequence++;
        TRACE() << "-------------------------------------\n";
        TRACE() << request;
        TRACE() << "-------------------------------------";
        _request_sent = _tcp.sendall(request.c_str(), request.length()) == int(request.length());
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \brief rtsp_class::_mess_response, all protcol goes here, messy but works
/// \param buf
/// \return
///
bool rtsp_class::_mess_response(const char* buf, size_t) {

    std::stringstream ss(buf);
    std::string line;
    bool        okays[2] = {false,false};
    int         seq = 0;

    const std::string what = _query.front();
    _request_sent = false;
    while(std::getline(ss, line, '\n') )
    {
        while(line.back()=='\r'||line.back()=='\n')
            line.pop_back();
        if(line.empty()){
            continue;
        }
        TRACE()<<"LINE: [" << line << "]\n";
        if(line.find(WWW_AUTH) != std::string::npos)
        {
            _hdrs[WWW_AUTH] = line.substr(18);
            okays[0]=true;
            okays[1]=true;
        }
        else if(line.find("200")!=std::string::npos)
        {
            okays[0]=true;
        }
        else if(line.find(CSEQ)!=std::string::npos)
        {
            ::sscanf(line.c_str(),"CSeq: %d",&seq);
            if(seq==_waitseq)
                okays[1] = true;
        }
        if(okays[0]==true &&
                okays[1]==true)
            break;
    }

    if(okays[0] && okays[1])
    {
        int   emptylines = 0;
        while(std::getline(ss, line, '\n'))
        {
            while(line.back()=='\r'||line.back()=='\n'){
                line.pop_back();
            }
            if(line.empty()){
                emptylines++;
                continue;
            }
            TRACE()<<"LINE: [" << line << "]\n";
            for(int i=0; __hdrs[i]; i++)
            {
                size_t ptok = line.find(__hdrs[i]);
                if(ptok != std::string::npos)
                {
                    std::string param = line.substr(ptok + ::strlen(__hdrs[i]));
                    size_t eop = param.find_last_of(';');
                    param = param.substr(0,eop);
                    _hdrs[ __hdrs[i] ] = param;
                    TRACE()<<"HDR: ["<< __hdrs[i] << "]=>'" << param << "'\n";
                }
            }
            // get SDP from these
            if(what=="DESCRIBE" || what=="SETUP")
            {
                for(int i=0; __sdps[i]; i++)
                {
                    if(line.compare(0,::strlen(__sdps[i]),__sdps[i])==0)
                    {
                        std::string param = line.substr(::strlen(__sdps[i]));
                        _sdps[ __sdps[i] ] = param;
                        TRACE()<< "SDP: [" <<__sdps[i] << "]=>'" << param << "'\n";
                    }
                }
            }
        }
        // reconf the UDP ports is server wants
        if(what=="SETUP")
        {
            int okays = 0;
            if(!_hdrs[CLI_PORT].empty())
            {
                TRACE()<<_hdrs[CLI_PORT]<<"\n";
                okays+=sscanf(_hdrs[CLI_PORT].c_str(),"%d-%d",_client_ports,_client_ports+1);
            }
            if(!_hdrs[SRV_PORT].empty())
            {
                TRACE()<<_hdrs[SRV_PORT]<<"\n";
                okays+=sscanf(_hdrs[SRV_PORT].c_str(),"%d-%d",_server_ports,_server_ports+1);
            }
            if(okays==4)
            {
                _spawn_udp();
            }
        }

        // overload but happends once
        if(_auth_hdr.empty())
        {
            const auto reqauto = _hdrs.find(WWW_AUTH);
            if(reqauto != _hdrs.end())
            {
                _authenticate();
            }
            else
            {
                _query.pop_front();
            }
        }
        else {
            _query.pop_front();
        }

    }

    // see if the stream have dimensions
    if(what=="PLAY"){
        const std::map<std::string, std::string>::iterator& dims = _sdps.find(SDP_XDIM);
        if(dims != _sdps.end())
        {
            ::sscanf(dims->second.c_str(),"%d,%d",&_dims[0],&_dims[1]);
        }
    }

    TRACE() << "-------------------------------------";
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
bool rtsp_class::_spawn_udp()
{
    if( _create_udp(_client_ports[0], _client_ports[1]))
    {
        const unsigned char natpacket[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        return _udp.send(natpacket, sizeof(natpacket),_server_ports[0], _host.c_str() )>0;
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/// \brief rtsp_class::_authenticate  BASIC ONLY
/// \return
///
bool rtsp_class::_authenticate()
{
    //WWW-Authenticate: Basic realm="rtspsvc"
    if(!_credentials.empty())
    {
        std::string up = base64_encode((const unsigned char*)_credentials.c_str(), _credentials.length());
        char buf[1024];
        _auth_hdr = HDR_ABASIC;
        _auth_hdr += up.c_str();
        _auth_hdr += "\r\n";

        sprintf(buf, "OPTIONS * RTSP/1.0\r\n"
                     "%s"
                     "\r\n", _auth_hdr.c_str());
        TRACE()<<buf<<"\n";
        int bytes =  _tcp.sendall(buf, strlen(buf));
        if(bytes>0)
        {
            bytes = _tcp.receive(buf, sizeof(buf));
            if(bytes>0)
            {
                TRACE()<<buf<<"\n";
                return ::strstr(buf,"200") != nullptr  ? true: false;
            }
            return false;
        }
    }
    return true;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
void rtsp_class::_do_udp(const uint8_t *buf, size_t bufsize, frame_load& frame)
{
    _rtp_parse((unsigned char*)buf,bufsize, frame);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool rtsp_class::cmd_play(std::string url, const std::string& credentials)
{
    int     port = 0;
    char    scheme[8];
    char    host[128];
    char    path[128];

    _rtspurl = url;
    _credentials = credentials;
    _reset();
    parseURL(url.c_str(), scheme,
             sizeof(scheme), host, sizeof(host),
             &port, path, sizeof(path));
    _uri  = path;
    _host = host;
    if(_tcp.create(port))
    {
        if(_tcp.try_connect(host, port))
        {
            _seed();
            return true;
        }
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool rtsp_class::spin(frame_load& frame)
{
    bool rv = true;
    int  r;
    _seed();
    r = _harvest();
    if (r & TIO_RD)
    {
        int recvbytes = _tcp.receive(_recvbuf, CHUNK_LEN);
        if (recvbytes <= 0) {
            _tcp.destroy();
            return false;
        }
        else
        {
            TRACE() << _recvbuf << "\n";
            _mess_response((const char*)_recvbuf, recvbytes);
        }
    }

    if (r & UIO_RD)
    {
        size_t recvbytes = _udp.receive(_recvbuf, CHUNK_LEN);
        if(recvbytes>0)
        {
            _do_udp(_recvbuf, recvbytes, frame);
        }
        if(recvbytes==0){
            // conn closed;
            rv = false;
        }
    }

    if (r & USIO_RD)
    {
        // discard audio
        rv = _udp.receive(_recvbuf, CHUNK_LEN)  > 0;
    }

    if (r & TIO_WR)
    {
        _send_request();
    }

    if (r & TIO_ER)
    {
        TRACE() << "socket error\n";
        return false;
    }

    return rv;
}


void    rtsp_class::_seed(){
    FD_ZERO(&_readfd);
    FD_ZERO(&_writefd);
    FD_ZERO(&_errorfd);
    if(_tcp.isopen()){
        _maxfd = std::max(_maxfd, _tcp.socket());
        FD_SET(_tcp.socket(), &_readfd);
        FD_SET(_tcp.socket(), &_writefd);
        FD_SET(_tcp.socket(), &_errorfd);
    }
    if(_udp.isopen()){
        _maxfd = std::max(_maxfd, _udp.socket());
        FD_SET(_udp.socket(), &_readfd);
        FD_SET(_udp.socket(), &_writefd);
        FD_SET(_udp.socket(), &_errorfd);
    }
    if(_udpc.isopen()){
        _maxfd = std::max(_maxfd, _udpc.socket());
        FD_SET(_udpc.socket(), &_readfd);
        FD_SET(_udpc.socket(), &_writefd);
        FD_SET(_udpc.socket(), &_errorfd);
    }
}
int rtsp_class::_harvest()
{
    struct timeval tv = {0,10000};
    int r = ::select(_maxfd + 1, &_readfd, &_writefd, &_errorfd, &tv);
    if(r < 0){
        TRACE()<< "network system error \n";
        return -1;
    }
    else if(r>0)
    {
        r = 0;
        if(_udpc.isopen())
        {
            r |= FD_ISSET(_udpc.socket(), &_readfd)  ? USIO_RD : 0;
            r |= FD_ISSET(_udpc.socket(), &_writefd) ? USIO_WR : 0;
            r |= FD_ISSET(_udpc.socket(), &_errorfd) ? USIO_ER : 0;
        }
        if(_udp.isopen())
        {
            r |= FD_ISSET(_udp.socket(), &_readfd)  ? UIO_RD : 0;
            r |= FD_ISSET(_udp.socket(), &_writefd) ? UIO_WR : 0;
            r |= FD_ISSET(_udp.socket(), &_errorfd) ? UIO_ER : 0;
        }
        if(_tcp.isopen())
        {
            r |= FD_ISSET(_tcp.socket(), &_readfd)  ? TIO_RD  : 0;
            r |= FD_ISSET(_tcp.socket(), &_writefd) ? TIO_WR  : 0;
            r |= FD_ISSET(_tcp.socket(), &_errorfd) ? TIO_ER  : 0;
        }
        return r;
    }
    return 0;
}

bool   rtsp_class::_create_udp(int port, int portc)
{
    _udp.destroy();
    _udpc.destroy();

    if(!_udp.create(port))
    {
        return false;
    }
    if(!_udp.bind(0,port))
    {
        return false;
    }
    if(!_udpc.create(portc))
    {
        return false;
    }
    if(!_udpc.bind(0,portc))
    {
        return false;
    }
    return true;
}

void rtsp_class::stop()
{
    _udp.destroy();
    _udpc.destroy();
    _tcp.destroy();
}


void rtsp_class::_rtp_stats_print()
{
    if(__debug){

        printf(">> RTP Stats\n");
        printf("   First Sequence  : %u\n", _rtp_st.first_seq);
        printf("   Highest Sequence: %u\n", _rtp_st.highest_seq);
        printf("   RTP Received    : %u\n", _rtp_st.rtp_received);
        printf("   RTP Identifier  : %u\n", _rtp_st.rtp_identifier);
        printf("   RTP Timestamp   : %u\n", _rtp_st.rtp_ts);
        printf("   Jitter          : %u\n", _rtp_st.jitter);
        printf("   Last DLSR       : %i\n", _rtp_st.last_dlsr);
    }
}

void rtsp_class::_rtp_stats_update(struct rtp_header *rtp_h)
{
    uint32_t transit;
    int delta;
    struct timeval now;

    gettimeofday(&now, NULL);
    _rtp_st.rtp_received++;

    /* Highest sequence */
    if (rtp_h->seq > _rtp_st.highest_seq) {
        _rtp_st.highest_seq = rtp_h->seq;
    }


    /* Update RTP timestamp */
    if (_rtp_st.last_rcv_time.tv_sec == 0) {
        //_rtp_st.rtp_ts = rtp_h->ts;
        _rtp_st.first_seq = rtp_h->seq;
        //_rtp_st.jitter = 0;
        //_rtp_st.last_dlsr = 0;
        //_rtp_st.rtp_cum_lost = 0;
        gettimeofday(&_rtp_st.last_rcv_time, NULL);

        /* deltas
        int sec  = (rtp_h->ts / RTP_FREQ);
        int usec = (((rtp_h->ts % RTP_FREQ) / (RTP_FREQ / 8000))) * 125;
        _rtp_st.ts_delta.tv_sec  = now.tv_sec - sec;
        _rtp_st.ts_delta.tv_usec = now.tv_usec - usec;


        _rtp_st.last_arrival = rtp_tval2rtp(_rtp_st.ts_delta.tv_sec,
                                           _rtp_st.ts_delta.tv_usec);
        _rtp_st.last_arrival = rtp_tval2RTP(now);

    }
    else {*/
    }
    /* Jitter */
    transit = _rtp_st.delay_snc_last_SR;
    //printf("TRANSIT!: %i\n", transit); exit(1);
    delta = transit - _rtp_st.transit;
    _rtp_st.transit = transit;
    if (delta < 0) {
        delta = -delta;
    }
    //printf("now = %i ; rtp = %i ; delta = %i\n",
    //       t, rtp_h->ts, delta);
    //_rtp_st.jitter += delta - ((_rtp_st.jitter + 8) >> 4);
    _rtp_st.jitter += ((1.0/16.0) * ((double) delta - _rtp_st.jitter));

    _rtp_st.rtp_ts = rtp_h->ts;
    //}

    /* print the new stats */
    _rtp_stats_print();
}


int rtsp_class::_write_nal(frame_load& frame)
{
    uint8_t nal_header[4] = {0x00, 0x00, 0x00, 0x01};
    frame.append(nal_header,sizeof(nal_header));
    return 1;
}

int rtsp_class::_write_afternal(const void *buf, size_t count, frame_load& frame, bool done)
{
    /* write to pipe */
    frame.append((const uint8_t*)buf,count);
    if(done){
        frame.ready();
    }
    return 1;
}

int rtsp_class::_rtp_parse(unsigned char *raw, int size, frame_load& frame)
{
    int raw_offset = 0;
    int rtp_length = size;
    int paysize;
    unsigned char payload[8912];
    struct rtp_header rtp_h;

    rtp_h.version = raw[raw_offset] >> 6;
    rtp_h.padding = CHECK_BIT(raw[raw_offset], 5);
    rtp_h.extension = CHECK_BIT(raw[raw_offset], 4);
    rtp_h.cc = raw[raw_offset] & 0xFF;

    /* next byte */
    raw_offset++;

    rtp_h.marker = CHECK_BIT(raw[raw_offset], 8);
    rtp_h.pt     = raw[raw_offset] & 0x7f;

    /* next byte */
    raw_offset++;

    /* Sequence number */
    rtp_h.seq = raw[raw_offset] * 256 + raw[raw_offset + 1];
    raw_offset += 2;

    /* time stamp */
    rtp_h.ts = \
            (raw[raw_offset    ] << 24) |
            (raw[raw_offset + 1] << 16) |
            (raw[raw_offset + 2] <<  8) |
            (raw[raw_offset + 3]);
    raw_offset += 4;

    /* ssrc / source identifier */
    rtp_h.ssrc = \
            (raw[raw_offset    ] << 24) |
            (raw[raw_offset + 1] << 16) |
            (raw[raw_offset + 2] <<  8) |
            (raw[raw_offset + 3]);
    raw_offset += 4;
    _rtp_st.rtp_identifier = rtp_h.ssrc;

    /* Payload size */
    paysize = (rtp_length - raw_offset);

    memset(payload, '\0', sizeof(payload));
    memcpy(&payload, raw + raw_offset, paysize);

    /*
     * A new RTP packet has arrived, we need to pass the rtp_h struct
     * to the stats/context updater
     */
    _rtp_stats_update(&rtp_h);
    /* Display RTP header info */
    if(__debug){

        printf("   >> RTP\n");
        printf("      Version     : %i\n", rtp_h.version);
        printf("      Padding     : %i\n", rtp_h.padding);
        printf("      Extension   : %i\n", rtp_h.extension);
        printf("      CSRC Count  : %i\n", rtp_h.cc);
        printf("      Marker      : %i\n", rtp_h.marker);
        printf("      Payload Type: %i\n", rtp_h.pt);
        printf("      Sequence    : %i\n", rtp_h.seq);
        printf("      Timestamp   : %u\n", rtp_h.ts);
        printf("      Sync Source : %u\n", rtp_h.ssrc);
    }
    /*
     * NAL, first byte header
     *
     *   +---------------+
     *   |0|1|2|3|4|5|6|7|
     *   +-+-+-+-+-+-+-+-+
     *   |F|NRI|  Type   |
     *   +---------------+
     */
    int nal_forbidden_zero = CHECK_BIT(payload[0], 7);
    int nal_nri  = (payload[0] & 0x60) >> 5;
    int nal_type = (payload[0] & 0x1F);

    if(__debug){
        printf("      >> NAL\n");
        printf("         Forbidden zero: %i\n", nal_forbidden_zero);
        printf("         NRI           : %i\n", nal_nri);
        printf("         Type          : %i\n", nal_type);
    }


    /* Single NAL unit packet */
    if (nal_type >= NAL_TYPE_SINGLE_NAL_MIN &&
            nal_type <= NAL_TYPE_SINGLE_NAL_MAX) {

        /* Write NAL header */

        _write_nal(frame);

        /* Write NAL unit */
        _write_afternal(payload, sizeof(paysize), frame);
    }

    /*
     * Agregation packet - STAP-A
     * ------
     * http://www.ietf.org/rfc/rfc3984.txt
     *
     * 0                   1                   2                   3
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                          RTP Header                           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |STAP-A NAL HDR |         NALU 1 Size           | NALU 1 HDR    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                         NALU 1 Data                           |
     * :                                                               :
     * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |               | NALU 2 Size                   | NALU 2 HDR    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                         NALU 2 Data                           |
     * :                                                               :
     * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                               :...OPTIONAL RTP padding        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    else if (nal_type == NAL_TYPE_STAP_A) {
        uint8_t *q;
        uint16_t nalu_size;

        q = payload + 1;
        int nidx = 0;

        nidx = 0;
        while (nidx < paysize - 1) {
            /* write NAL header */
            _write_nal(frame);

            /* get NALU size */
            nalu_size = (q[nidx] << 8) | (q[nidx + 1]);
            printf("nidx = %i ; NAL size = %i ; RAW offset = %i\n",
                   nidx, nalu_size, raw_offset);
            nidx += 2;

            /* write NALU size */
            _write_afternal(&nalu_size, 1, frame);

            if (nalu_size == 0) {
                nidx++;
                continue;
            }

            /* write NALU data */
            _write_afternal(q + nidx, nalu_size, frame);
            nidx += nalu_size;
        }
    }
    else if (nal_type == NAL_TYPE_FU_A) {
        //printf("         >> Fragmentation Unit\n");

        uint8_t *q;
        q = payload;

        uint8_t h264_start_bit = q[1] & 0x80;
        uint8_t h264_end_bit   = q[1] & 0x40;
        uint8_t h264_type      = q[1] & 0x1F;
        uint8_t h264_nri       = (q[0] & 0x60) >> 5;
        uint8_t h264_key       = (h264_nri << 5) | h264_type;

        if (h264_start_bit) {
            /* write NAL header */
            _write_nal(frame);

            /* write NAL unit code */
            _write_afternal(&h264_key, sizeof(h264_key),frame);
        }
        _write_afternal(q + 2, paysize - 2,frame);

        if (h264_end_bit) {
            frame.ready();
        }
    }
    else if (nal_type == NAL_TYPE_UNDEFINED) {
    }
    else {
        printf("OTHER NAL!: %i\n", nal_type);
        raw_offset++;

    }
    raw_offset += paysize;

    if (rtp_h.seq > _rtp_st.highest_seq) {
        _rtp_st.highest_seq = rtp_h.seq;
    }

    _rtp_stats_print();
    return raw_offset;
}




static constexpr char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                       "abcdefghijklmnopqrstuvwxyz"
                                       "0123456789+/";

static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';

    }
    return ret;
}


static int parseURL(const char* url, char* scheme, size_t
                    maxSchemeLen, char* host, size_t maxHostLen,
                    int* port, char* path, size_t maxPathLen) //Parse URL
{
    (void)maxPathLen;
    char* schemePtr = (char*) url;
    char* hostPtr = (char*) strstr(url, "://");
    if(hostPtr == NULL)
    {
        printf("Could not find host");
        return 0; //URL is invalid
    }

    if( maxSchemeLen < (size_t)(hostPtr - schemePtr + 1 )) //including NULL-terminating char
    {
        printf("Scheme str is too small (%zu >= %zu)", maxSchemeLen,
               hostPtr - schemePtr + 1);
        return 0;
    }
    memcpy(scheme, schemePtr, hostPtr - schemePtr);
    scheme[hostPtr - schemePtr] = '\0';

    hostPtr+=3;

    size_t hostLen = 0;

    char* portPtr = strchr(hostPtr, ':');
    if( portPtr != NULL )
    {
        hostLen = portPtr - hostPtr;
        portPtr++;
        if( sscanf(portPtr, "%d", port) != 1)
        {
            printf("Could not find port");
            return 0;
        }
    }
    else
    {
        *port=80;
    }
    char* pathPtr = strchr(hostPtr, '/');
    if( hostLen == 0 )
    {
        hostLen = pathPtr - hostPtr;
    }

    if( maxHostLen < hostLen + 1 ) //including NULL-terminating char
    {
        printf("Host str is too small (%zu >= %zu)", maxHostLen, hostLen + 1);
        return 0;
    }
    memcpy(host, hostPtr, hostLen);
    host[hostLen] = '\0';

    size_t pathLen;
    char* fragmentPtr = strchr(hostPtr, '#');
    if(fragmentPtr != NULL)
    {
        pathLen = fragmentPtr - pathPtr;
    }
    else
    {
        if(pathPtr)
            pathLen = strlen(pathPtr);
        else
            pathLen=0;
    }

    if(pathPtr)
    {
        memcpy(path, pathPtr, pathLen);
        path[pathLen] = '\0';
    }
    else
    {
        path[0]=0;
    }

    return 1;
}

