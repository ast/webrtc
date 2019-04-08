%%%-------------------------------------------------------------------
%%% @author albin
%%% @copyright (C) 2019, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 07. Apr 2019 14:44
%%%-------------------------------------------------------------------
-module(gen_gnutls).
-author("albin").

-behaviour(gen_server).

-on_load(load_nifs/0).

%% API
-export([start_link/0,
  start/0,
  send/2,
  open_nif/2,
  srtp_get_keys/1,
  cookie_verify_nif/3,
  srtp_get_keys_nif/1,
  cookie_send_nif/2,
  handshake_nif/2,
  record_recv_nif/2,
  record_send_nif/2]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-record(state, {socket, ip, port, ref, state}).

%%%===================================================================
%%% API
%%%===================================================================

load_nifs() ->
  NifPath = filename:join([code:priv_dir(webrtc), "webrtc"]),
  ok = erlang:load_nif(NifPath, 0).

send(ServerRef, Data) when is_binary(Data) ->
  gen_server:call(ServerRef, {send_dtls, Data}).

srtp_get_keys(ServerRef) ->
  gen_server:call(ServerRef, srtp_get_keys).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
  gen_server:start_link(?MODULE, [], []).

start() ->
  gen_server:start(?MODULE, [], []).

open_nif(_Certfile, _Keyfile) ->
  not_loaded(?LINE).

cookie_verify_nif(_Ref, _ClientData, _Data) ->
  not_loaded(?LINE).

cookie_send_nif(_Ref, _ClientData) ->
  not_loaded(?LINE).

handshake_nif(_Ref, _Data) ->
  not_loaded(?LINE).

srtp_get_keys_nif(_Ref) ->
  not_loaded(?LINE).

record_recv_nif(_Ref, _Data) ->
  not_loaded(?LINE).

record_send_nif(_Ref, _Data) ->
  not_loaded(?LINE).

not_loaded(Line) ->
  exit({not_loaded, [{module, ?MODULE}, {line, Line}]}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
  {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term()} | ignore).
init([]) ->
  Certfile = filename:join([code:priv_dir(webrtc), "cert.pem"]),
  Keyfile = filename:join([code:priv_dir(webrtc), "key.pem"]),
  {ok, Socket} = gen_udp:open(7373, [binary]),
  {ok, Ref} = open_nif(Certfile, Keyfile),
  {ok, #state{socket = Socket, ref = Ref, state=cookie}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
    State :: #state{}) ->
  {reply, Reply :: term(), NewState :: #state{}} |
  {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
  {stop, Reason :: term(), NewState :: #state{}}).

handle_call(srtp_get_keys, _From, #state{ref=Ref, state=connected} = State) ->
  Keys = srtp_get_keys_nif(Ref),
  {reply, Keys, State};

handle_call({send_dtls, Data}, _From, #state{socket=Socket, ip=Ip, port=Port, ref=Ref, state=connected} = State) ->
  [Packet] = record_send_nif(Ref, Data),
  io:format("send ~p~n", [Packet]),
  gen_udp:send(),
  {reply, ok, State};

handle_call(_Request, _From, State) ->
  {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_cast(Request :: term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_cast(_Request, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).

handle_info({udp, Socket, Ip, Port, Data}, #state{ref = Ref, state = connected} = State) ->
  io:format("data: ~p~n", [Data]),
  case record_recv_nif(Ref, Data) of
    {ok, Clear} ->
      io:format("clear: ~p~n", [Clear]),
      {noreply, State};
    {error, Reason} ->
      io:format("error: ~p~n", [Reason]),
      {noreply, State}
  end;

handle_info({udp, Socket, Ip, Port, Data}, #state{ref = Ref, state = cookie} = State) ->
  ClientData = term_to_binary([Ip, Port]),
  case cookie_verify_nif(Ref, ClientData, Data) of
    ok ->
      % save Ip and Port and only accept these
      {noreply, State#state{state=handshake, ip=Ip, port=Port}};
    {error, Reason} ->
      % Retry that
      {ok, [Cookie]} = cookie_send_nif(Ref, ClientData),
      ok = gen_udp:send(Socket, Ip, Port, Cookie),
      {noreply, State}
  end;

handle_info({udp, Socket, Ip, Port, Data}, #state{ref = Ref, ip=Ip, port=Port, state = handshake} = State) ->
  case handshake_nif(Ref, Data) of
    {again, []} ->
      {noreply, State};
    {again, Packets} ->
      % send packets
      [ok = gen_udp:send(Socket, Ip, Port, Packet) || Packet <- Packets],
      {noreply, State};
    {ok, Packets} ->
      [ok = gen_udp:send(Socket, Ip, Port, Packet) || Packet <- Packets],
      {noreply, State#state{state=connected}}
  end;

handle_info(Info, State) ->
  io:format("info: ~p~n", [Info]),
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
    State :: #state{}) -> term()).
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
    Extra :: term()) ->
  {ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
