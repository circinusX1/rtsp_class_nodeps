#ifndef REAPLCE_THIS_WITH_YOUR_IMPL
#define REAPLCE_THIS_WITH_YOUR_IMPL

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

///////////////////////////////////////////////////////////////////////////////////////////////////
#define TRACE() std::cout

///////////////////////////////////////////////////////////////////////////////////////////////////
#define     INITIAL_LEN         32768
#define     STEP_LEN            4096
#define     MAX_LEN             80000

///////////////////////////////////////////////////////////////////////////////////////////////////
/// \brief The frame_load class
///  Added, for the sake of thes demo
class frame_load
{
public:
    frame_load(int cap=INITIAL_LEN):cap(INITIAL_LEN),len(0){
        buf = new uint8_t[cap];
        _ready = false;
        assert(buf);
    }
    ~frame_load(){
        delete[] buf;
    }
    size_t ptr(const uint8_t** pb)const{
        *pb = buf;
        return len;
    }
    bool realloc(size_t nlen){
        if(nlen > cap){
            size_t newcap = ((nlen/STEP_LEN)+1)*STEP_LEN;
            assert(newcap<MAX_LEN);
            uint8_t* pnewbuf = new uint8_t[newcap];
            if(pnewbuf){
                if(len){
                    ::memcpy(pnewbuf, buf, len);
                }
                delete[] buf;
                cap = newcap;
                return true;
            }
            return  false;
        }
        return true;
    }
    void ready(){_ready=true;};
    void un_ready(){_ready=false;};
    void append(const uint8_t* p, size_t nlen)
    {
        copy(p,len,nlen);
    }
    void copy(const uint8_t* p, size_t off, size_t nlen)
    {
        bool real=true;

        if(nlen > cap){
            real=realloc(nlen);
        }
        if(real){
            ::memcpy(buf+off, p, nlen);
            len = nlen+off;
        }else{
            len=0;
        }
    }
    void    set_len(size_t l){len=l;}
    size_t  length()const{return len;}
    size_t  capa()const{return cap;}
    size_t  room()const{return cap-len;}
    void    reset(){len=0;_ready = false;};
    uint8_t*     buffer(int off=0){
        return buf+off;
    }
    bool is_ready()const{return _ready;}
    int    _wh[2];
private:
    uint8_t* buf=nullptr;
    size_t  cap=0;
    size_t  len=0;
    bool    _ready;
};

///////////////////////////////////////////////////////////////////////////////////////////////////
/// \brief The tcp_cli_sock class
///
class tcp_cli_sock{
    int _thesock = 0;
public:
    tcp_cli_sock(){}
    ~tcp_cli_sock(){destroy();}
    template<typename T>int sendall(const T* buff, int length){
        int loops = length/256 + 1;
        int sent = 0;
        while(length > 0 &&  loops-->0){
            int shot = ::send(_thesock,(char *)buff+sent, length,  MSG_NOSIGNAL);
            if(shot<=0){
                break;
            }
            length -= shot;
            sent   += shot;
        }
        return sent;
    }
    template<typename T>int receive(T* buff, int length){
        return ::recv(_thesock,(char *)buff, length, 0);
    }
    int create(int){
        _thesock = ::socket(AF_INET, SOCK_STREAM, 0);
        return _thesock;
    }
    int try_connect(const char* sip, int port)
    {
        assert((int)_thesock > 0); // create first
        hostent  *_hostent = ::gethostbyname(sip);
        if(_hostent==0)
        {
            long dwbo = inet_addr(sip);
            _hostent = gethostbyaddr((char*)&dwbo, (int)sizeof(dwbo), AF_INET );
        }
        if(!_hostent)
        {
            return 0;
        }
        struct sockaddr_in rsin;
        ::memcpy((char*)&(rsin.sin_addr), _hostent->h_addr, _hostent->h_length);
        rsin.sin_family		= AF_INET;
        rsin.sin_port		= htons(port);
        if(-1 == ::connect(_thesock, (const struct sockaddr*)&rsin, sizeof(struct sockaddr_in))){
            if(errno==EINPROGRESS){
                fd_set writeFDS;
                fd_set exceptFDS;

                //  Clear all the socket FDS structures
                FD_ZERO( &writeFDS );
                FD_ZERO( &exceptFDS );

                //  Put the socket into the FDS structures
                FD_SET( _thesock, &writeFDS );
                FD_SET( _thesock, &exceptFDS );
                timeval timeout={30,0};
                int selectReturn = ::select( _thesock + 1
                                             , NULL
                                             , &writeFDS
                                             , &exceptFDS
                                             , &timeout);

                if ( selectReturn == 0 ){
                    return 0;
                }
                if ( FD_ISSET( _thesock, &writeFDS ) ){
                    return _thesock;
                }
                if ( FD_ISSET( _thesock, &exceptFDS ) ){
                    return 0;
                }
            }
            return 0;
        }
        return _thesock;
    }
    void destroy(){if(_thesock > 0) ::close(_thesock);_thesock=0;}
    bool isopen()const{return _thesock>0;}
    int socket()const{return _thesock;}
};


///////////////////////////////////////////////////////////////////////////////////////////////////
/// \brief The udp_sock class
///
class udp_sock{
    int _thesock = 0;
    bool _bind = false;
    struct sockaddr_in _remote_sin;
    struct sockaddr_in _local_sin;
public:
    int  send(const unsigned char* buff,
              const int length,
              int port, const char* ip)
    {
        struct sockaddr_in rsin;
        rsin.sin_port        = htons (port);
        rsin.sin_family      = AF_INET;
        if(ip)
            rsin.sin_addr.s_addr = inet_addr(ip); // direct
        else
            rsin.sin_addr.s_addr = inet_addr("255.255.255.255");
        return ::sendto(_thesock, (char*)buff, length, 0,
                        (struct sockaddr  *) &rsin,
                        sizeof(struct sockaddr_in)) ;
    }
    int  receive(uint8_t* buff, int length)
    {
        socklen_t iRecvLen=(socklen_t)sizeof(struct sockaddr_in);
        int rcv =  (int)::recvfrom (_thesock,
                                    (char*)buff,
                                    length,
                                    0,
                                    (struct sockaddr  *) &_remote_sin,
                                    &iRecvLen);
        return rcv;

    }
    int create(int port, int proto=0, const char* addr=nullptr){
        assert(_thesock<=0);
        _thesock = ::socket(AF_INET, SOCK_DGRAM, proto);
        if((int)-1 == (int)_thesock)
            return -1;
        _local_sin.sin_family        = AF_INET;
        _local_sin.sin_addr.s_addr   = addr ? inet_addr(addr): htonl(INADDR_ANY);
        _local_sin.sin_port          = htons(port);
        return _thesock;
    }

    int  bind(const char* addr, int port)
    {
        if(addr)
            _local_sin.sin_addr.s_addr = inet_addr(addr);
        else
            _local_sin.sin_addr.s_addr = htonl(INADDR_ANY);
        if(port)
            _local_sin.sin_port = htons(port);
        assert(_local_sin.sin_port > 0); //did you pass in at create the addr and port
        if(::bind(_thesock,(struct sockaddr *)&_local_sin, sizeof(struct sockaddr_in)))
        {
            printf("udp-sock-bind-error\n");
            perror("bind error \n");
            return -1;
        }
        return _thesock;
    }
    bool isopen()const{return _thesock>0;}
    int socket()const{return _thesock;}
    void destroy(){if(_thesock > 0) ::close(_thesock);_thesock=0;}
};

///////////////////////////////////////////////////////////////////////////////////////////////////
/// \brief The pipiefile class
///
class pipiefile
{
public:
    pipiefile(std::string file):_fd(0),_print(false)
    {
        std::string pipefile = file;
        std::vector<std::string>  fn;

        if(::access(pipefile.c_str(),0)==0)
        {
            ::unlink(pipefile.c_str());
        }

        int fi = ::mkfifo(pipefile.c_str(),O_RDWR|O_NONBLOCK| S_IRWXU|S_IRWXG|S_IRWXG  );
        if(fi<0)
        {
            perror("mkfifo");
            return;
        }
        _fd = ::open (pipefile.c_str(),O_RDWR|O_CREAT);
        if(_fd<0)
        {
            TRACE() << file << ": PIPE: " << strerror(errno);
        }
        else
        {
            _fn = pipefile;
            ::fcntl(_fd,F_SETFL,O_NONBLOCK);
            ::fcntl(_fd,F_SETPIPE_SZ,1024 * 8912);
        }
        if(!_print)
        {
            TRACE() << "new pipe: "<< _fn << "\n";
            _print=true;
        }
    }

    ~pipiefile()
    {
        if(_fd)
            ::close(_fd);
        ::unlink(_fn.c_str());
        TRACE() << "delete pipe: "<< _fn << "\n";
    }


    int stream(const uint8_t* buff,size_t maxsz)
    {
        if(_fd & maxsz)
        {
            size_t rv;
            size_t sent = 0;
            do{
                rv =  ::write(_fd,buff+sent,maxsz-sent);
                if(rv==std::string::npos)
                {
                    break;
                }
                sent+=rv;
            }while(sent<maxsz);
            return sent;
        }
        return 0;
    }
    bool ok()const{return _fd>0;}

private:
    std::string _fn;
    int         _fd;
    bool        _print;
};

#endif // REAPLCE_THIS_WITH_YOUR_IMPL

