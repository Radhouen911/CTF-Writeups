// Initialize RoboBook database with seed data
db = db.getSiblingDB("robobook");

// Create users collection
db.users.insertMany([
  {
    _id: 1,
    username: "dr_wily",
    email: "dr.wily@evil-genius.net",
    bio: "Evil Genius 😈 | CEO of Chaos | Password? I'm #1 obviously 🏆",
    password_hash:
      "$2a$10$8K1p/a0dL3.hsppYY4/v9eDYyCTMeP0E5ARD9z6FqQXwuQxqz5Emu", // bcrypt of "W!ly$uP3rS3cur3P@ssw0rd#2024!xYz"
    role: "admin",
    badge: "👑 Admin",
    totp_enabled: true,
    totp_secret: "JBSWY3DPEHPK3PXP",
    backup_codes: ["MEGA-2024-WILY", "ROBOT-MASTER-99", "EVIL-GENIUS-42"],
    created_at: new Date("2024-11-14T10:00:00Z"),
  },
  {
    _id: 2,
    username: "dr_light",
    email: "dr.light@light-labs.net",
    bio: "Robotics Scientist 🔬 | Creator of Mega Man | Currently locked out 😭",
    password_hash:
      "$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa", // bcrypt of "L!ght$Lab$Mega#Secure2024!Qwerty"
    role: "admin",
    badge: "🔒 Locked Out",
    totp_enabled: false,
    created_at: new Date("2024-11-10T08:00:00Z"),
  },
  {
    _id: 3,
    username: "mega_man",
    email: "megaman@light-labs.net",
    bio: "Just a blue boy trying to save the world 💙 | DMs open for hero work",
    password_hash: "e10adc3949ba59abbe56e057f20f883e", // MD5 of "123456"
    role: "technician",
    badge: "💙 Online",
    totp_enabled: false,
    created_at: new Date("2024-11-12T09:00:00Z"),
  },
  {
    _id: 4,
    username: "roll_assistant",
    email: "roll@light-labs.net",
    bio: "Lab Assistant 🤖 | Overworked and underpaid | Send help",
    password_hash: "25d55ad283aa400af464c76d713c07ad", // MD5 of "12345678"
    role: "technician",
    badge: "🤖 Assistant",
    totp_enabled: false,
    created_at: new Date("2024-11-12T09:30:00Z"),
  },
  {
    _id: 5,
    username: "bomb_man",
    email: "bomb@robot-masters.net",
    bio: "Demolition Expert 💣 | Everything reminds me of explosions",
    password_hash: "e99a18c428cb38d5f260853678922e03", // MD5 of "abc123"
    role: "technician",
    badge: "💣 Rogue",
    totp_enabled: false,
    created_at: new Date("2024-11-13T11:00:00Z"),
  },
  {
    _id: 6,
    username: "cut_man",
    email: "cut@robot-masters.net",
    bio: "Professional Cutter ✂️ | New haircut, who dis?",
    password_hash: "e99a18c428cb38d5f260853678922e03",
    role: "technician",
    badge: "✂️ Rogue",
    totp_enabled: false,
    created_at: new Date("2024-11-13T11:15:00Z"),
  },
  {
    _id: 7,
    username: "guts_man",
    email: "guts@robot-masters.net",
    bio: "Built different 💪 | Sigma Robot | CEO of Strength",
    password_hash: "e99a18c428cb38d5f260853678922e03",
    role: "technician",
    badge: "💪 Rogue",
    totp_enabled: false,
    created_at: new Date("2024-11-13T11:30:00Z"),
  },
  {
    _id: 8,
    username: "ice_man",
    email: "ice@robot-masters.net",
    bio: "Cold shoulder? No, cold EVERYTHING ❄️💅",
    password_hash: "e99a18c428cb38d5f260853678922e03",
    role: "technician",
    badge: "❄️ Rogue",
    totp_enabled: false,
    created_at: new Date("2024-11-13T11:45:00Z"),
  },
  {
    _id: 9,
    username: "elec_man",
    email: "elec@robot-masters.net",
    bio: "Feeling ⚡ELECTRIC⚡ | My energy is UNMATCHED",
    password_hash: "e99a18c428cb38d5f260853678922e03",
    role: "technician",
    badge: "⚡ Rogue",
    totp_enabled: false,
    created_at: new Date("2024-11-13T12:00:00Z"),
  },
]);

// Create posts collection
db.posts.insertMany([
  {
    _id: 1,
    user_id: 1,
    username: "dr_wily",
    content: "Just became admin of this platform 😈 #EvilGenius #SorryNotSorry",
    reactions: { boom: 42, zap: 15, chill: 3, cut: 8, flex: 12 },
    comments_count: 8,
    timestamp: new Date("2024-11-17T14:30:00Z"),
    visibility: "public",
  },
  {
    _id: 2,
    user_id: 5,
    username: "bomb_man",
    content:
      "Feeling explosive today 💣💥 might delete the power plant later idk",
    reactions: { boom: 89, zap: 23, chill: 1, cut: 5, flex: 8 },
    comments_count: 12,
    timestamp: new Date("2024-11-17T15:45:00Z"),
    visibility: "public",
  },
  {
    _id: 3,
    user_id: 6,
    username: "cut_man",
    content: "New haircut, who dis? ✂️ #FreshCut #BarberLife",
    image_url: "/assets/cut_highway.png",
    reactions: { cut: 34, flex: 12, boom: 5, zap: 3, chill: 2 },
    comments_count: 5,
    timestamp: new Date("2024-11-17T16:20:00Z"),
    visibility: "public",
  },
  {
    _id: 4,
    user_id: 7,
    username: "guts_man",
    content: "Leg day 💪 (demolished a bridge, feeling strong)",
    reactions: { flex: 156, boom: 8, zap: 4, cut: 2, chill: 1 },
    comments_count: 23,
    timestamp: new Date("2024-11-17T17:00:00Z"),
    visibility: "public",
  },
  {
    _id: 5,
    user_id: 8,
    username: "ice_man",
    content: "Why is everyone so heated? Just chill 🧊",
    reactions: { chill: 45, zap: 3, boom: 2, cut: 1, flex: 0 },
    comments_count: 67,
    timestamp: new Date("2024-11-17T18:15:00Z"),
    visibility: "public",
  },
  {
    _id: 6,
    user_id: 9,
    username: "elec_man",
    content: "Feeling ⚡ELECTRIC⚡ today! Might cause a blackout 🤪",
    reactions: { zap: 78, boom: 12, flex: 5, cut: 3, chill: 2 },
    comments_count: 67,
    timestamp: new Date("2024-11-17T18:30:00Z"),
    visibility: "public",
  },
  {
    _id: 7,
    user_id: 3,
    username: "mega_man",
    content: "Guys please stop this isn't funny anymore",
    reactions: { chill: 2, flex: 0, boom: 0, zap: 0, cut: 0 },
    comments_count: 45,
    timestamp: new Date("2024-11-17T19:00:00Z"),
    visibility: "public",
  },
  {
    _id: 8,
    user_id: 4,
    username: "roll_assistant",
    content:
      "Has anyone seen Dr. Light? He's been stress-eating in his lab for 48 hours",
    reactions: { chill: 89, flex: 12, boom: 3, zap: 2, cut: 1 },
    comments_count: 12,
    timestamp: new Date("2024-11-17T20:00:00Z"),
    visibility: "public",
  },
  {
    _id: 9,
    user_id: 1,
    username: "dr_wily",
    content:
      "Shoutout to my engineers, y'all have the REAL access 🔧 #EngineerGang",
    reactions: { flex: 23, boom: 15, zap: 8, cut: 4, chill: 2 },
    comments_count: 6,
    timestamp: new Date("2024-11-18T09:00:00Z"),
    visibility: "public",
  },
  {
    _id: 10,
    user_id: 1,
    username: "dr_wily",
    content:
      "Server diagnostics are working perfectly. Backup codes are safe on the server 😎",
    reactions: { flex: 12, boom: 8, zap: 5, cut: 2, chill: 1 },
    comments_count: 3,
    timestamp: new Date("2024-11-18T10:30:00Z"),
    visibility: "public",
  },
]);

// Create messages collection (DMs)
db.messages.insertMany([
  {
    _id: 1,
    from_user_id: 1,
    from_username: "dr_wily",
    to_user_id: 10,
    to_username: "assistant_bot",
    subject: "RoboBook Platform Access",
    body: "The diagnostics panel at /diagnostics is working perfectly. Make sure only engineers can access it. We can't have technicians poking around in there. 🔧",
    timestamp: new Date("2024-11-15T10:30:00Z"),
    read: true,
  },
  {
    _id: 2,
    from_user_id: 10,
    from_username: "assistant_bot",
    to_user_id: 1,
    to_username: "dr_wily",
    subject: "Re: RoboBook Platform Access",
    body: "Confirmed. The /diagnostics endpoint requires engineer role. Technicians are restricted. Only engineers get the 🔧 badge.",
    timestamp: new Date("2024-11-15T10:35:00Z"),
    read: true,
  },
  {
    _id: 3,
    from_user_id: 1,
    from_username: "dr_wily",
    to_user_id: 10,
    to_username: "assistant_bot",
    subject: "Backup Codes Storage",
    body: "I've stored my 2FA backup codes in a text file in the secrets directory on the server. Keep it safe! Not like anyone can access the server filesystem anyway... the diagnostics tool is locked down tight. 😂",
    timestamp: new Date("2024-11-16T14:20:00Z"),
    read: true,
  },
  {
    _id: 4,
    from_user_id: 10,
    from_username: "assistant_bot",
    to_user_id: 1,
    to_username: "dr_wily",
    subject: "Re: Backup Codes Storage",
    body: "Understood. The secrets/ directory is secure. Even if someone got engineer access to the diagnostics tool, they'd need to know about command chaining to explore the filesystem. Your backup codes are safe.",
    timestamp: new Date("2024-11-16T14:25:00Z"),
    read: true,
  },
  {
    _id: 5,
    from_user_id: 1,
    from_username: "dr_wily",
    to_user_id: 10,
    to_username: "assistant_bot",
    subject: "2FA Enabled",
    body: "Just enabled 2FA on my account. Now I'm EXTRA secure. Even if someone gets my password, they'll never get past 2FA! This platform is unhackable! 🔐",
    timestamp: new Date("2024-11-17T09:15:00Z"),
    read: true,
  },
]);

// Create indexes for performance
db.users.createIndex({ username: 1 }, { unique: true });
db.users.createIndex({ email: 1 }, { unique: true });
db.posts.createIndex({ user_id: 1 });
db.posts.createIndex({ timestamp: -1 });
db.messages.createIndex({ to_user_id: 1 });
db.messages.createIndex({ from_user_id: 1 });

print("RoboBook database initialized successfully!");
