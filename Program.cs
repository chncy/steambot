using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Collections.Generic;
using System.Net;

using SteamKit2;
using SteamKit2.Internal;

using SteamKit2.GC;
using SteamKit2.GC.Internal;

using SteamKit2.GC.CSGO;
using SteamKit2.GC.CSGO.Internal;

using MySql.Data.MySqlClient;
using System.Text.RegularExpressions;
using System.Globalization;

namespace SteamBot {

	class Program {
		static SteamClient steamClient;
		static CallbackManager manager;

		static SteamUser steamUser;
		static SteamFriends steamFriends;
        static SteamGameCoordinator gameCoordinator;

		static MySql.Data.MySqlClient.MySqlConnection conn;
		static string mysqlAuth;

		static bool isRunning;

		static string user, pass;
		static string authCode, twoFactorAuth;

		static string apikey = "#";

		static SteamID chncy = new SteamID("STEAM_0:1:56709769");

		enum linkStatus {
			entered,
			linked,
			synced
		};

		enum task {
			kill,
			restart,
			start,
            stop
		};

        static String[] ranks = {
            "Unranked",
            "Silver I",
            "Silver II",
            "Silver III",
            "Silver IV",
            "Silver Elite",
            "Silver Elite Master",
            "Gold Nova I",
            "Gold Nova II",
            "Gold Nova III",
            "Gold Nova Master",
            "Master Guardian I",
            "Master Guardian II",
            "Master Guardian Elite",
            "Distinguished Master Guardian",
            "Legendary Eagle",
            "Legendary Eagle Master",
            "Supreme Master First Class",
            "The Global Elite"
        };

		static string me = "steambot";

		static void Main(string[] args) {

			if (args.Length < 2) {
				Console.WriteLine("[ STEAMBOT ] Missing arguments! Usage: program <user> <password>");
				return;
			}
			user = args[0];
			pass = args[1];

			// Set MySQL auth
			mysqlAuth = "#";

			steamClient = new SteamClient();
			//  create the callback manager which will route callbacks to function calls
			manager = new CallbackManager(steamClient);

			SteamDirectory.Initialize().Wait();

			steamUser = steamClient.GetHandler<SteamUser>();
			steamFriends = steamClient.GetHandler<SteamFriends>();
            gameCoordinator = steamClient.GetHandler<SteamGameCoordinator>();

			// Handle Callbacks with functions
			// DOCUMENTATION: check c# delegates and eventhandlers

			// Connected and Disconnected (SteamClient)
			manager.Subscribe<SteamClient.ConnectedCallback>(OnConnected);
			manager.Subscribe<SteamClient.DisconnectedCallback>(OnDisconnected);

			// Logon and Logoff (SteamUser)
			manager.Subscribe<SteamUser.LoggedOnCallback>(OnLoggedOn);
			manager.Subscribe<SteamUser.LoggedOffCallback>(OnLoggedOff);

			// Callback for when steam servers ask for sentry file storing
			manager.Subscribe<SteamUser.UpdateMachineAuthCallback>(OnMachineAuth);

			// Callbacks for Friends related activities
			manager.Subscribe<SteamUser.AccountInfoCallback>(OnAccountInfo);
			manager.Subscribe<SteamFriends.FriendsListCallback>(OnFriendsList);
			manager.Subscribe<SteamFriends.FriendAddedCallback>(OnFriendAdded);
			manager.Subscribe<SteamFriends.FriendMsgCallback>(OnFriendMsg);
			manager.Subscribe<SteamFriends.PersonaStateCallback>(OnPersonaState);

            manager.Subscribe<SteamGameCoordinator.MessageCallback>(OnGCMessage);

			isRunning = true;

			Console.WriteLine("[ STEAMCLIENT ] Connecting to Steam...");

			steamClient.Connect();


			// Loop to handle callbacks
			while (isRunning) {
				// In order for the callbacks to get routed, they need to be handled by the manager
				
				manager.RunWaitCallbacks(TimeSpan.FromSeconds(1));
			}

		}

		static void OnConnected(SteamClient.ConnectedCallback callback) {
			if (callback.Result != EResult.OK) {
				Console.WriteLine("[ STEAMCLIENT ] Unable to connect to Steam: {0}", callback.Result);

				isRunning = false;
				return;
			}

			Console.WriteLine("[ STEAMCLIENT ] Connected to Steam! Logging in with account '{0}'...", user);

			byte[] sentryHash = null;
			if (File.Exists(user + ".bin")) {
				// If we have a saved sentry file, read and sha-1 hash it
				byte[] sentryFile = File.ReadAllBytes(user + ".bin");
				sentryHash = CryptoHelper.SHAHash(sentryFile);
			}

			steamUser.LogOn(new SteamUser.LogOnDetails {
				Username = user,
				Password = pass,
				AuthCode = authCode,
				TwoFactorCode = twoFactorAuth,
				SentryFileHash = sentryHash,
				ShouldRememberPassword = true
			});
		}

		static void OnDisconnected(SteamClient.DisconnectedCallback callback) {
			// Receiving AccountLogonDenied automatically disconnects you from Steam
			// After getting the Authcode from the User we need to reconnect

			Console.WriteLine("[ STEAMCLIENT ] Disconnected from Steam, reconnecting in 3s...");

			Thread.Sleep(TimeSpan.FromSeconds(3));

			steamClient.Connect();
		}

		static void OnLoggedOn(SteamUser.LoggedOnCallback callback) {
			bool isSteamGuard = callback.Result == EResult.AccountLogonDenied;
			bool is2FA = callback.Result == EResult.AccountLoginDeniedNeedTwoFactor;

			if (isSteamGuard || is2FA) {
				Console.WriteLine("[ STEAMUSER ] This account is SteamGuard protected!");

				if (is2FA) {
					Console.WriteLine("[ STEAMUSER ] Please enter your 2 factor auth code from your authenticator app: ");
					twoFactorAuth = Console.ReadLine();
				} else {
					Console.WriteLine("[ STEAMUSER ] Please enter the auth code sent to the email at {0}: ", callback.EmailDomain);
					authCode = Console.ReadLine();
				}

				return;
			}

			if (callback.Result != EResult.OK) {

				Console.WriteLine("[ STEAMUSER ] Unable to logon to Steam: {0} / {1}", callback.Result, callback.ExtendedResult);

				if (callback.Result == EResult.ServiceUnavailable) {

					Console.WriteLine("[ STEAMUSER ] Retrying logon in 10s...");

					Thread.Sleep(TimeSpan.FromSeconds(10));
					Console.WriteLine("/             Disconnecting from Steam...");
					steamClient.Disconnect();
					Console.WriteLine("\\             Reconnecting to Steam...");
					steamClient.Connect();

					return;
				}

				isRunning = false;
				return;
			}

			Console.WriteLine("[ STEAMUSER ] Successfully logged on!");

		}

		static void OnAccountInfo(SteamUser.AccountInfoCallback callback) {
			steamFriends.SetPersonaName("/r/obot");
			steamFriends.SetPersonaState(EPersonaState.Online);

            ClientMsgProtobuf<CMsgClientGamesPlayed> request = new ClientMsgProtobuf<CMsgClientGamesPlayed>(EMsg.ClientGamesPlayed);

            request.Body.games_played.Add(new CMsgClientGamesPlayed.GamePlayed {
                game_id = new GameID(730)
            });

            steamClient.Send(request);

			GCGreet();

			Console.WriteLine("[ STEAMFRIENDS ] Set PersonaName to '/r/obot' and set PersonaState to Online.");
		}

		static void OnFriendsList(SteamFriends.FriendsListCallback callback) {
			// At this point, the client has received it's friends list
			// Iterate over Friendslist to accept received friend requests
            
			foreach (var friend in callback.FriendList) {
				if (friend.Relationship == EFriendRelationship.RequestRecipient) {
					steamFriends.AddFriend(friend.SteamID);
				}
                
			}
		}

		static void OnPersonaState(SteamFriends.PersonaStateCallback callback) {
			if (!callback.FriendID.IsIndividualAccount || callback.FriendID.Equals(steamClient.SteamID)) return;
			if (callback.GameAppID == 730) CSGOPlayerInfo(callback.FriendID, 32);
		}

		static void OnFriendAdded(SteamFriends.FriendAddedCallback callback) {
			Console.WriteLine("[ STEAMFRIENDS ] {0} added as Friend.", callback.PersonaName);
		}

		static void OnFriendMsg(SteamFriends.FriendMsgCallback callback) {
            try{
                using(conn = new MySql.Data.MySqlClient.MySqlConnection(mysqlAuth)) {
                    conn.Open();
                    SteamID sid = callback.Sender;
                    ulong sid64 = callback.Sender.ConvertToUInt64();
                    string name = steamFriends.GetFriendPersonaName(sid);
                    int timestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    string message = callback.Message;

                    if (callback.Message.Length > 0 && !callback.Message.Equals(" ")) {

                        Console.WriteLine("[ MESSAGE ] {0} sent a message: \"{1}\"", name, callback.Message);

                        
                        // ADMIN COMMANDS
                        //
                        //
                        // Schedule restarts

                        if(callback.Message.ToLower().StartsWith("commend"))
							sendCommend(callback.Sender);

						if (callback.Message.ToLower().StartsWith("rank"))
							CSGOPlayerInfo(callback.Sender, 32);

						if (callback.Message.ToLower().StartsWith("restart") && message.Length > 9) {
                            try {
                                int serviceid;
                                int t = message.IndexOf("-t");
                                int d = message.IndexOf("-d");
                                int x = message.Length;
                                long execution = timestamp;

                                if (t > 0 && d > 0) throw new FormatException();

                                if (t > 0) {

                                    execution = timestamp + Int32.Parse(message.Substring(t+3));
                                    x = t;

                                } else if (d > 0) {

                                    execution = new DateTimeOffset(DateTime.ParseExact(message.Substring(d+3), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)).ToUnixTimeSeconds();
                                    x = d;

                                }

                                string service = message.Substring(8, x - 9);

                                if (!callback.Sender.Equals(chncy)) {

                                    Console.WriteLine("[ SCHEDULING ] {0} requested a restart of {1}, timestamp: {2}, but is not allowed to!", name, service, timestamp);

                                } else {

                                    Console.WriteLine("[ SCHEDULING ] Admin requested a restart of {1}, timestamp: {2}", name, service, timestamp);
                                    bool numeric = Regex.IsMatch(message.Substring(8), @"^\d+$");

                                    if (numeric) {
                                        serviceid = Int32.Parse(message.Substring(8));
                                    }

                                    try {

                                        MySqlCommand cmd = new MySqlCommand();
                                        cmd.Connection = conn;
                                        cmd.CommandText = "INSERT INTO schedules.schedules (autor, task, service, exec_at, timestamp, type) VALUES (@autor, @task, @service, @exec_at, @timestamp, 1)";
                                        cmd.Prepare();

                                        cmd.Parameters.AddWithValue("@autor", me + " - " + name);
                                        cmd.Parameters.AddWithValue("@task", (int)task.restart);
                                        cmd.Parameters.AddWithValue("@service", service);
                                        cmd.Parameters.AddWithValue("@exec_at", execution);
                                        cmd.Parameters.AddWithValue("@timestamp", timestamp);
                                        cmd.ExecuteNonQuery();
                                        cmd.Dispose();

                                        steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Successfully scheduled restart of " + service + ". Waiting for service to respond!");
                                        Console.WriteLine("[ SCHEDULING ] Succesfully scheduled restart of {0}.", service);

                                    } catch (MySqlException ex) {
                                        switch (ex.Number) {
                                            default:
                                                Console.WriteLine("[ SCHEDULING ] Error Scheduling Restart - ({0}) MySQL Exception: {1}", ex.Number, ex.ToString());
                                                steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "It appears we encountered an error trying :("
                                                                                                                + " Please contact http://steamcommunity.com/id/chncy/");
                                                break;
                                        }
                                    }
                                }
                            } catch (FormatException ex) {

                                Console.WriteLine("[ SCHEDULING ] {0} Syntax Error!", name);
                                steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Syntax error! Check your date! " + ex.Message);

                            }
                        }

                        // LINK ACCOUNTS

                        if (callback.Message.ToLower().StartsWith("link")) {

                            Console.Write("[ ACCOUNTLINK ] {0} requested link...", name);
                            steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Linking your Steam Account...");

                            try {

                                MySqlCommand cmd = new MySqlCommand();
                                cmd.Connection = conn;
                                cmd.CommandText = "INSERT INTO users_steam (steamid, token, timestamp, status) VALUES (@sid, @token, @timestamp, 0)";
                                cmd.Prepare();

                                Random r = new Random();
                                String hash = Base64Encode((r.Next(2048) + name).ToString());

                                cmd.Parameters.AddWithValue("@sid", sid64.ToString());
                                cmd.Parameters.AddWithValue("@token", hash);
                                cmd.Parameters.AddWithValue("@timestamp", timestamp);
                                cmd.ExecuteNonQuery();
                                cmd.Dispose();

                                steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Succesfully linked your Steam Account! Hash: " + hash);
                                Console.Write(" Success!");

                            } catch (MySqlException ex) {
                                switch (ex.Number) {
                                    case 1062:
                                        Console.Write(" Error - User already in Database!\n");
                                        steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "You're already in our Database!");
                                        break;
                                    default:
                                        Console.Write(" Error - ({0}) MySQL Exception: {1}\n", ex.Number, ex.ToString());
                                        steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "It appears we encountered an error linking your Account :("
                                                                                                        + " Please contact http://steamcommunity.com/id/chncy/");
                                        break;
                                }
                            }
                        }

                        // SYNC GAMES TO EXISTING ACCOUNT

                        if (callback.Message.ToLower().StartsWith("check")) {


                            Console.Write("[ SYNCING ] {0} requested a sync...", name);
                            steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Syncing your Steam Account Information...");
                            try {

                                MySqlCommand cmd = new MySqlCommand();
                                cmd.Connection = conn;
                                cmd.CommandText = "UPDATE users_steam SET games_owned = @gamesowned, last_sync = @timestamp, status = 2 WHERE steamid = @sid";
                                cmd.Prepare();

                                String[] games = GetOwnedGames(sid64, 1, 0);

                                cmd.Parameters.AddWithValue("@sid", sid64.ToString());
                                cmd.Parameters.AddWithValue("@timestamp", timestamp);
                                cmd.Parameters.AddWithValue("@gamesowned", string.Join("# ", games));
                                cmd.ExecuteNonQuery();
                                cmd.Dispose();

                                steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Succesfully synced your Steam Account.");
                                Console.Write(" Success!\n");

                            } catch (MySqlException ex) {
                                Console.Write(" Error - ({0}) MySQL Exception: {1}\n", ex.Number, ex.ToString());
                                steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "It appears we encountered an error syncing your Information :("
                                                                                                + " Please contact http://steamcommunity.com/id/chncy/");
                            }
                        }

                        // ISCHECKED?

                        if (callback.Message.ToLower().StartsWith("?check")) {

                            steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Fetching Database Status...");
                            try {

                                MySqlCommand cmd = new MySqlCommand();
                                cmd.Connection = conn;
                                cmd.CommandText = "SELECT * FROM users_steam WHERE steamid = @sid";
                                cmd.Parameters.AddWithValue("@sid", sid64.ToString());
                                cmd.Prepare();

                                using (MySqlDataReader reader = cmd.ExecuteReader()) {
                                    if (!reader.HasRows) {
                                        reader.Close();
                                        steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "You are not in our Database!");
                                    } else {
                                        while (reader.Read()) {
                                            if (reader.FieldCount > 0) {

                                                int status = reader.GetInt32("status");
                                                if (status == (int)linkStatus.entered) {

                                                    steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Please finish your linking process!");
                                                } else {

                                                    int uid = reader.GetInt32("uid");
                                                    int dbid = reader.GetInt32("dbid");
                                                    int linked = reader.GetInt32("timestamp");

                                                    DateTime dtLinked = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
                                                    dtLinked = dtLinked.AddSeconds(linked).ToLocalTime();

                                                    steamFriends.SendChatMessage(sid, EChatEntryType.ChatMsg, "Linked Account found!\nOverview: \n"
                                                    + "Linked at: " + dtLinked + "\n"
                                                    + "User ID: " + uid + "\n"
                                                    + "TS3 Database ID: " + dbid);
                                                }
                                            }
                                        }
                                    }
                                }
                                cmd.Dispose();
                            } catch (MySqlException ex) {
                                Console.WriteLine(ex.ToString());
                            }
                        }
                    }
                    conn.Close();
                }
            } catch (MySql.Data.MySqlClient.MySqlException ex) {
				Console.WriteLine("[ MYSQL ] Error connecting to MySQL-Server: {0}", ex.Message);
			}
		}

        //GAME COORDINATOR
        static void OnGCMessage(SteamGameCoordinator.MessageCallback callback) {

            var messageMap = new Dictionary<uint, Action<IPacketGCMsg>> {
                {(uint) EGCBaseClientMsg.k_EMsgGCClientWelcome, OnClientWelcome},
                //{(uint) ECsgoGCMsg.k_EMsgGCCStrike15_v2_MatchmakingGC2ClientHello, OnClientHello},
                {(uint) ECsgoGCMsg.k_EMsgGCCStrike15_v2_PlayersProfile, OnPlayerInfo},
            };

            Action<IPacketGCMsg> func;
            if (!messageMap.TryGetValue(callback.EMsg, out func)) {
                // UNHANDLED MESSAGES
                if(callback.EMsg != 4009)
                    Console.WriteLine("[ GAMECOORDINATOR ] Unhandled Message: {0}, {1}", callback.EMsg, callback.Message);
                return;
            }

            func(callback.Message);
        }

        static void OnClientWelcome(IPacketGCMsg packetMsg) {
            // in order to get at the contents of the message, we need to create a ClientGCMsgProtobuf from the packet message we recieve
            // note here the difference between ClientGCMsgProtobuf and the ClientMsgProtobuf used when sending ClientGamesPlayed
            // this message is used for the GC, while the other is used for general steam messages
            var msg = new ClientGCMsgProtobuf<CMsgClientWelcome>(packetMsg);

            Console.WriteLine("[ GAMECOORDINATOR ] GC is welcoming us.");

            // at this point, the GC is now ready to accept messages from us

        }

		static void GCGreet() {
			Console.WriteLine("[ GAMECOORDINATOR ] Greeting Game Coordinator.");
			var clientHello = new ClientGCMsgProtobuf<CMsgClientHello>((uint)EGCBaseClientMsg.k_EMsgGCClientHello);

			gameCoordinator.Send(clientHello, 730);
		}

        static void sendCommend(SteamID steamid) {
            
            Console.WriteLine("[ GAMECOORDINATOR ] Trying to commend player {0}", steamid.ConvertToUInt64());

            var commend = new ClientGCMsgProtobuf<CMsgGCCStrike15_v2_ClientCommendPlayer>((uint) ECsgoGCMsg.k_EMsgGCCStrike15_v2_ClientCommendPlayer);
            commend.Body.account_id = steamid.AccountID;
            commend.Body.commendation = new PlayerCommendationInfo {
                cmd_friendly = 1,
                cmd_teaching = 2,
                cmd_leader = 4
            };
            commend.Body.match_id = 8;
            commend.Body.tokens = 10;
            gameCoordinator.Send(commend, 730);
        }

        /*static void OnClientHello(IPacketGCMsg packetMsg) {
            var msg = new ClientGCMsgProtobuf<CMsgGCCStrike15_v2_MatchmakingGC2ClientHello>(packetMsg);

            CMsgGCCStrike15_v2_MatchmakingGC2ClientHello stats = msg.Body;

            Console.WriteLine("[ STEAMFRIENDS ] Player {0} is playing CS:GO, fetching player info!", msg.Body.account_id);

			if(stats.commendation == null) {
				stats.commendation.cmd_friendly = 0;
				stats.commendation.cmd_leader = 0;
				stats.commendation.cmd_teaching = 0;
			}

            using(conn = new MySql.Data.MySqlClient.MySqlConnection(mysqlAuth)) {
                try {
                    conn.Open();

                    MySqlCommand cmd = new MySqlCommand();
                    cmd.Connection = conn;
                    cmd.CommandText = "INSERT INTO steam.csgo_stats (steamid, rank_id, wins, commendation, medal_arms, medal_combat, medal_global, medal_team, medal_weapon, player_level, vac)"
                    + " VALUES (@sid, @rank, @wins, @comm, @ma, @mc, @mg, @mt, @mw, @level, @vac)" 
                    + " ON DUPLICATE KEY UPDATE rank_id=VALUES(rank_id), wins=VALUES(wins), commendation=VALUES(commendation), medal_arms=VALUES(medal_arms),"
					+ "medal_combat=VALUES(medal_combat), medal_global=VALUES(medal_global), medal_team=VALUES(medal_team), medal_weapon=VALUES(medal_weapon), player_level=VALUES(player_level), vac=VALUES(vac);";

                    cmd.Parameters.AddWithValue("@sid", stats.account_id);
                    cmd.Parameters.AddWithValue("@rank", stats.ranking.rank_id);
                    cmd.Parameters.AddWithValue("@wins", stats.ranking.wins);
                    cmd.Parameters.AddWithValue("@comm", (stats.commendation.cmd_friendly + ", " + stats.commendation.cmd_leader + ", " + stats.commendation.cmd_teaching));
                    cmd.Parameters.AddWithValue("@ma", stats.medals.medal_arms);
                    cmd.Parameters.AddWithValue("@mc", stats.medals.medal_combat);
                    cmd.Parameters.AddWithValue("@mg", stats.medals.medal_global);
                    cmd.Parameters.AddWithValue("@mt", stats.medals.medal_team);
                    cmd.Parameters.AddWithValue("@mw", stats.medals.medal_weapon);
                    cmd.Parameters.AddWithValue("@level", stats.player_level);
                    cmd.Parameters.AddWithValue("@vac", stats.vac_banned);

                    cmd.ExecuteNonQuery();

                    conn.Close();
                } catch(MySqlException e) {

					Console.WriteLine("[ GAMECOORDINATOR ] Error Inserting Player - ({0}) MySQL Exception: {1}", e.Number, e.ToString());                            
                }
            }
        }*/

        static void CSGOPlayerInfo(SteamID steamid, uint requestlevel) {

            Console.Write("[ GAMECOORDINATOR ] Fetching Player-Profile of {0}...", steamFriends.GetFriendPersonaName(steamid));

            var request = new ClientGCMsgProtobuf<CMsgGCCStrike15_v2_ClientRequestPlayersProfile>((uint) ECsgoGCMsg.k_EMsgGCCStrike15_v2_ClientRequestPlayersProfile);
            request.Body.account_id = steamid.AccountID;
            request.Body.request_level = requestlevel;
            gameCoordinator.Send(request, 730);
        }

        static void OnPlayerInfo(IPacketGCMsg packetMsg) {
            CMsgGCCStrike15_v2_MatchmakingGC2ClientHello stats = null;

            try {
                ClientGCMsgProtobuf<CMsgGCCStrike15_v2_PlayersProfile> msg = new ClientGCMsgProtobuf<CMsgGCCStrike15_v2_PlayersProfile>(packetMsg);
                
                stats = msg.Body.account_profiles[0];
            } catch(ArgumentOutOfRangeException e) {
				Console.Write(" Error - Player might not be Ingame (yet)!\n");
                return;
            }

			string sid = (stats.account_id + 76561197960265728) + "";

			using (conn = new MySql.Data.MySqlClient.MySqlConnection(mysqlAuth)) {
                try {
                    conn.Open();

                    MySqlCommand cmd = new MySqlCommand();
                    cmd.Connection = conn;
                    cmd.CommandText = "INSERT INTO steam.csgo_stats (steamid, rank_id, wins, commendation, medal_arms, medal_combat, medal_global, medal_team, medal_weapon, player_level, vac)"
                    + " VALUES (@sid, @rank, @wins, @comm, @ma, @mc, @mg, @mt, @mw, @level, @vac)" 
                    + " ON DUPLICATE KEY UPDATE rank_id=VALUES(rank_id), wins=VALUES(wins), commendation=VALUES(commendation), medal_arms=VALUES(medal_arms)," 
                    + "medal_combat=VALUES(medal_combat), medal_global=VALUES(medal_global), medal_team=VALUES(medal_team), medal_weapon=VALUES(medal_weapon), player_level=VALUES(player_level), vac=VALUES(vac);";

                    cmd.Parameters.AddWithValue("@sid", sid);
                    cmd.Parameters.AddWithValue("@rank", stats.ranking.rank_id);
                    cmd.Parameters.AddWithValue("@wins", stats.ranking.wins);
                    cmd.Parameters.AddWithValue("@comm", (stats.commendation.cmd_friendly + ", " + stats.commendation.cmd_leader + ", " + stats.commendation.cmd_teaching));
                    cmd.Parameters.AddWithValue("@ma", stats.medals.medal_arms);
                    cmd.Parameters.AddWithValue("@mc", stats.medals.medal_combat);
                    cmd.Parameters.AddWithValue("@mg", stats.medals.medal_global);
                    cmd.Parameters.AddWithValue("@mt", stats.medals.medal_team);
                    cmd.Parameters.AddWithValue("@mw", stats.medals.medal_weapon);
                    cmd.Parameters.AddWithValue("@level", stats.player_level);
                    cmd.Parameters.AddWithValue("@vac", stats.vac_banned);

                    cmd.ExecuteNonQuery();

                    conn.Close();

					Console.Write(" Success!\n");
                } catch(MySqlException e) {

                    Console.Write(" Error Inserting Player - ({0}) MySQL Exception: {1}\n", e.Number, e.ToString());
                }
            }
        }

		static void OnLoggedOff(SteamUser.LoggedOffCallback callback) {
			Console.WriteLine("[ STEAMUSER ] Logged off of Steam: {0}", callback.Result);
		}

		static void OnMachineAuth(SteamUser.UpdateMachineAuthCallback callback) {
			Console.WriteLine("[ STEAMAUTH ] Updating sentryfile...");

			// Write sentry file
			// Ideally we'd want to write to the filename specified in the callback
			// In this case using "sentry.bin"

			int fileSize;
			byte[] sentryHash;
			using (var fs = File.Open(user + ".bin", FileMode.OpenOrCreate, FileAccess.ReadWrite)) {
				fs.Seek(callback.Offset, SeekOrigin.Begin);
				fs.Write(callback.Data, 0, callback.BytesToWrite);
				fileSize = (int)fs.Length;

				fs.Seek(0, SeekOrigin.Begin);
				using (var sha = new SHA1CryptoServiceProvider()) {
					sentryHash = sha.ComputeHash(fs);
				}
			}

			// Inform the steam servers that we're accepting this sentry file
			steamUser.SendMachineAuthResponse(new SteamUser.MachineAuthDetails {
				JobID = callback.JobID,

				FileName = callback.FileName,

				BytesWritten = callback.BytesToWrite,
				FileSize = fileSize,
				Offset = callback.Offset,

				Result = EResult.OK,
				LastError = 0,

				OneTimePassword = callback.OneTimePassword,

				SentryFileHash = sentryHash,
			});

			Console.WriteLine(callback.FileName);

			Console.WriteLine("[ STEAMAUTH ] Done!");
		}

		public static string Base64Encode(string plainText) {
			var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
			return System.Convert.ToBase64String(plainTextBytes);
		}

		static String[] GetOwnedGames(SteamID sid, int appinfo, int freegames) {
			using (dynamic playerService = WebAPI.GetInterface("IPlayerService", apikey)) {

				playerService.Timeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;

				Dictionary<string, string> args = new Dictionary<string, string>();
				args["steamid"] = sid.ConvertToUInt64().ToString();
				args["include_appinfo"] = appinfo.ToString();
				args["include_played_free_games"] = freegames.ToString();

				try {
					KeyValue re = playerService.Call("GetOwnedGames", 1, args);
					int i = 0;
					String[] result = new String[re["games"].Children.Count];
					foreach (KeyValue game in re["games"].Children) {
						result[i] = game["appid"].AsString() + "= " + game["name"].AsString();
						i++;
					}
					return result;
				} catch (WebException ex) {
					Console.WriteLine("[ GETOWNEDGAMES ] Error: WebException - {0}", ex.Message);
					String[] result = { };
					return result;
				}
			}
		}

        static int InGame(SteamID sid) {
            using (dynamic ISteamUser = WebAPI.GetInterface("ISteamUser", apikey)) {

                ISteamUser.Timeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;

                Dictionary<string, string> args = new Dictionary<string, string>();
                args["steamids"] = sid.ConvertToUInt64().ToString();

                try {
                    KeyValue re = ISteamUser.Call("GetPlayerSummaries", 2, args);

                    if(re["players"].Children[0]["gameid"].Value != null) {
                        return Int32.Parse(re["players"].Children[0]["gameid"].Value);
                    } else return -1;
                } catch (WebException ex) {
                    Console.WriteLine("[ STEAMFRIENDS ] Error: WebException - {0}", ex.Message);
                    return -1;
                }
            }
        }
	}
}
