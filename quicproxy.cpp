/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
#include <msquichelper.h>
#include <stdio.h>
#include <string.h>

struct QuicProxyConnContext {
    HQUIC Conn;
    uint64_t RefCount;
};

struct QuicProxyStreamContext {
    HQUIC Conn;
    HQUIC Strm;
    uint64_t RefCount;
    uint64_t TotalBufferLength;
    QUIC_BUFFER Buffers[2];
    uint32_t BufferCount;
};

#define DEFAULT_PROXY_LISTEN_PORT 443
#define DEFAULT_PROXY_ALPN "h3"
#define DEFAULT_PROXY_STREAMS 100

//
// Exits if there is a failure.
//
#define EXIT_ON_FAILURE(x) do { \
    auto _Status = x; \
    if (QUIC_FAILED(_Status)) { \
       printf("%s:%d %s failed!\n", __FILE__, __LINE__, #x); \
       exit(1); \
    } \
} while (0);

//
// Globals
//
const QUIC_API_TABLE* MsQuic = nullptr;
HQUIC Registration = nullptr;
HQUIC ClientConfig = nullptr;
uint16_t DestPort = 0;
const char* DestAddrStr = nullptr;
QUIC_BUFFER Alpn{};

const char* UsageString =
    "Usage:"
    "  quicproxy.exe -listen:<addr or *> [-listenport:<###> (def:%u)]"
    "  -dest:<addr> -destport:<###>"
    "  -thumbprint:<cert thumbprint>"
    "  [-alpn:<str> (def:%s)] [-streams:<###> (def:%u)]";

void PrintUsage() {
    printf(UsageString, DEFAULT_PROXY_LISTEN_PORT, DEFAULT_PROXY_ALPN, DEFAULT_PROXY_STREAMS);
}
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
QuicProxyStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QuicProxyStreamContext* Peer = (QuicProxyStreamContext*)Context;
    QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;

    switch(Event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.BufferCount <= 2) {
            printf("RECEIVED MORE THAN 2 BUFFERS!!!!\n");
            exit(-1);
        }
        Peer->BufferCount = Event->RECEIVE.BufferCount;
        Peer->TotalBufferLength = Event->RECEIVE.TotalBufferLength;
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
            Peer->Buffers[i] = Event->RECEIVE.Buffers[i];
        }
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_0_RTT) {
            Flags |= QUIC_SEND_FLAG_ALLOW_0_RTT;
        }
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            Flags |= QUIC_SEND_FLAG_FIN;
        }

        if (QUIC_FAILED(
                Status = MsQuic->StreamSend(
                    Peer->Strm,
                    Peer->Buffers,
                    Peer->BufferCount,
                    Flags,
                    Peer))) {
            printf("Failed to send data on stream! 0x%x\n", Status);
            auto AbortFlags = QUIC_STREAM_SHUTDOWN_FLAG_ABORT | QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE;
            MsQuic->StreamShutdown(
                Stream,
                AbortFlags,
                0);
            MsQuic->StreamShutdown(
                Peer->Strm,
                AbortFlags,
                0);
            MsQuic->ConnectionShutdown(
                Peer->Conn,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                0);
            // TODO: figure out how to shutdown our connection from here
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Exit;
        }
        Status = QUIC_STATUS_PENDING;
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        QuicProxyStreamContext* Ctxt = (QuicProxyStreamContext*)Event->SEND_COMPLETE.ClientContext;
        MsQuic->StreamReceiveComplete(Peer->Strm, Ctxt->TotalBufferLength);
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic->StreamShutdown(
            Peer->Strm,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        MsQuic->StreamShutdown(
            Peer->Strm,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND,
            Event->PEER_SEND_ABORTED.ErrorCode);
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(
            Peer->Strm,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            Event->PEER_RECEIVE_ABORTED.ErrorCode);
        break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        // Do I need to do anything here?
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->StreamClose(Stream);
        free(Peer);
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
    default:
        break;
    }

Exit:
    return Status;
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
QuicProxyConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QuicProxyStreamContext* ThisStrmContext = nullptr;
    QuicProxyStreamContext* PeerStrmContext = nullptr;
    QuicProxyConnContext* Peer = (QuicProxyConnContext*)Context;
    switch(Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        MsQuic->ConnectionShutdown(
            Peer->Conn,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        MsQuic->ConnectionShutdown(
            Peer->Conn,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        free(Peer);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        ThisStrmContext = (QuicProxyStreamContext*)malloc(sizeof(QuicProxyStreamContext));
        PeerStrmContext = (QuicProxyStreamContext*)malloc(sizeof(QuicProxyStreamContext));
        if (!ThisStrmContext || !PeerStrmContext) {
            printf("Failed to allocate stream contexts!\n");
            Status = QUIC_STATUS_ABORTED;
        }
        ThisStrmContext->Conn = Peer->Conn;
        ThisStrmContext->RefCount = 1;
        PeerStrmContext->Conn = Connection;
        PeerStrmContext->Strm = Event->PEER_STREAM_STARTED.Stream;
        PeerStrmContext->RefCount = 1;

        if (QUIC_FAILED(
            Status = MsQuic->StreamOpen(
                Peer->Conn,
                Event->PEER_STREAM_STARTED.Flags,
                QuicProxyStreamCallback,
                PeerStrmContext,
                &ThisStrmContext->Strm))) {
            printf("Failed to open stream to peer 0x%x!\n", Status);
            MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            MsQuic->ConnectionShutdown(Peer->Conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            goto Fail;
        }

        if (QUIC_FAILED(
            Status = MsQuic->StreamStart(
                ThisStrmContext->Strm,
                QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL))) {
            printf("Failed to start stream to peer 0x%x!\n", Status);
            MsQuic->StreamClose(ThisStrmContext->Strm);
            MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            MsQuic->ConnectionShutdown(Peer->Conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            goto Fail;
        }

        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, QuicProxyStreamCallback, ThisStrmContext);
        break;
    }
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        MsQuic->ConnectionSendResumptionTicket(
            Peer->Conn,
            QUIC_SEND_RESUMPTION_FLAG_NONE,
            (uint16_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength,
            Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket);
        break;
    case QUIC_CONNECTION_EVENT_CONNECTED:
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
    case QUIC_CONNECTION_EVENT_RESUMED:
    default:
    // unused
    break;
    }

Fail:
    if (QUIC_FAILED(Status)) {
        free(ThisStrmContext);
        free(PeerStrmContext);
    }
    return Status;
}

_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
QuicProxyListenerCallback(
    _In_ HQUIC /*Listener*/,
    _In_opt_ void* /*Context*/,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QuicProxyConnContext* ThisContext = nullptr;
    QuicProxyConnContext* DestContext = nullptr;
    switch(Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        ThisContext = (QuicProxyConnContext*)malloc(sizeof(QuicProxyConnContext));
        DestContext = (QuicProxyConnContext*)malloc(sizeof(QuicProxyConnContext));
        if (!ThisContext || !DestContext) {
            printf("Failed to allocate context for connections\n!");
            Status = QUIC_STATUS_CONNECTION_REFUSED;
            goto Exit;
        }
        ThisContext->RefCount = 1;
        DestContext->RefCount = 1;

        DestContext->Conn = Event->NEW_CONNECTION.Connection;
        if (QUIC_FAILED(
            Status = MsQuic->ConnectionOpen(
                Registration,
                QuicProxyConnectionCallback,
                DestContext,
                &ThisContext->Conn))) {
            printf("Failed to create connection to destination 0x%x!\n", Status);
            Status = QUIC_STATUS_CONNECTION_REFUSED;
            goto Exit;
        }
        if (QUIC_FAILED(
            Status = MsQuic->ConnectionStart(
                ThisContext->Conn,
                ClientConfig,
                QUIC_ADDRESS_FAMILY_UNSPEC,
                DestAddrStr,
                DestPort))) {
            printf("Failed to start connection to destination 0x%x!\n", Status);
            MsQuic->ConnectionClose(ThisContext->Conn);
            Status= QUIC_STATUS_CONNECTION_REFUSED;
            goto Exit;
        }
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, QuicProxyConnectionCallback, ThisContext);
        break;
    }
    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
        break;
    }

Exit:
    if (QUIC_FAILED(Status)) {
        free(ThisContext);
        free(DestContext);
    }
    return Status;
}


int main(int argc, char **argv) {
    uint16_t ListenPort = DEFAULT_PROXY_LISTEN_PORT;
    TryGetValue(argc, argv, "listenport", &ListenPort);

    const char* AlpnStr = DEFAULT_PROXY_ALPN;
    TryGetValue(argc, argv, "alpn", &AlpnStr);
    Alpn = {(uint32_t)strnlen(AlpnStr, QUIC_MAX_ALPN_LENGTH), (uint8_t*)AlpnStr};

    uint16_t MaxStreams = DEFAULT_PROXY_STREAMS;
    TryGetValue(argc, argv, "streams", &MaxStreams);

    //
    // Required parameters.
    //
    const char* ListenAddrStr = nullptr;
    QUIC_ADDR ListenAddr = {};
    if (!TryGetValue(argc, argv, "listen", &ListenAddrStr) ||
        !ConvertArgToAddress(ListenAddrStr, ListenPort, &ListenAddr)) {
        printf("Missing or invalid '-listen' arg!\n");
        return -1;
    }

    if (!TryGetValue(argc, argv, "destport", &DestPort) ||
        !TryGetValue(argc, argv, "dest", &DestAddrStr)) {
        printf("Missing or invalid '-dest' or '-destport' arg!\n");
        return -1;
    }

    EXIT_ON_FAILURE(MsQuicOpen2(&MsQuic));
    const QUIC_REGISTRATION_CONFIG RegConfig = { "quicproxy", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    EXIT_ON_FAILURE(MsQuic->RegistrationOpen(&RegConfig, &Registration));

    QUIC_SETTINGS Settings{};
    Settings.PeerBidiStreamCount = MaxStreams;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.PeerUnidiStreamCount = MaxStreams;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    Settings.SendBufferingEnabled = FALSE;
    Settings.IsSet.SendBufferingEnabled = TRUE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;

    HQUIC Configuration =
        GetServerConfigurationFromArgs(
            argc,
            argv,
            MsQuic,
            Registration,
            &Alpn, 1,
            &Settings, sizeof(Settings));
    if (!Configuration) {
        printf("Failed to load configuration from args!\n");
        return -1;
    }

    QUIC_CREDENTIAL_CONFIG ClientCredConfig{};
    ClientCredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (QUIC_FAILED(
            MsQuic->ConfigurationOpen(
                Registration,
                &Alpn,
                1,
                &Settings,
                sizeof(Settings),
                nullptr,
                &ClientConfig)) ||
        QUIC_FAILED(
            MsQuic->ConfigurationLoadCredential(
                ClientConfig,
                &ClientCredConfig))) {
        printf("Failed to create and load client configuration!\n");
        return -1;
    }

    HQUIC Listener;
    if (QUIC_FAILED(
        MsQuic->ListenerOpen(
            Registration,
            QuicProxyListenerCallback,
            nullptr,
            &Listener))) {
        printf("Failed to create proxy listener!\n");
        return -1;
    }

    if (QUIC_FAILED(MsQuic->ListenerStart(Listener, &Alpn, 1, &ListenAddr))) {
        printf("Failed to start proxy listener!\n");
        return -1;
    }

    printf("Press Enter to exit.\n\n");
    getchar();

    MsQuic->ListenerStop(Listener);
    MsQuic->ListenerClose(Listener);
    FreeServerConfiguration(MsQuic, Configuration);
    MsQuic->ConfigurationClose(ClientConfig);
    MsQuic->RegistrationShutdown(
        Registration,
        QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
        0);
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);
}