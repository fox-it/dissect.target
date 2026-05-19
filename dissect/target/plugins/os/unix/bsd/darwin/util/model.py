from __future__ import annotations

# Reference: https://theapplewiki.com/wiki/Models
# Does not include Mac models.
MODELS = {
    # Apple TV
    # "Unknown": ("Apple TV (1st gen)", "AppleTV1,1"),
    "K66AP": ("Apple TV (2nd gen)", "AppleTV2,1"),
    "J33AP": ("Apple TV (3rd gen)", "AppleTV3,1"),
    "J33iAP": ("Apple TV (3rd gen)", "AppleTV3,2"),
    "J42dAP": ("Apple TV HD", "AppleTV5,3"),
    "J105aAP": ("Apple TV 4K", "AppleTV6,2"),
    "J305AP": ("Apple TV 4K (2nd gen)", "AppleTV11,1"),
    "J255AP": ("Apple TV 4K (3rd gen)", "AppleTV14,1"),
    # Apple Watch
    "N27aAP": ("Apple Watch (1st gen)", "Watch1,1"),
    "N28aAP": ("Apple Watch (1st gen)", "Watch1,2"),
    "N27dAP": ("Apple Watch Series 1", "Watch2,6"),
    "N28dAP": ("Apple Watch Series 1", "Watch2,7"),
    "N74AP": ("Apple Watch Series 2", "Watch2,3"),
    "N75AP": ("Apple Watch Series 2", "Watch2,4"),
    "N111sAP": ("Apple Watch Series 3", "Watch3,1"),
    "N111bAP": ("Apple Watch Series 3", "Watch3,2"),
    "N121sAP": ("Apple Watch Series 3", "Watch3,3"),
    "N121bAP": ("Apple Watch Series 3", "Watch3,4"),
    "N131sAP": ("Apple Watch Series 4", "Watch4,1"),
    "N131bAP": ("Apple Watch Series 4", "Watch4,2"),
    "N141sAP": ("Apple Watch Series 4", "Watch4,3"),
    "N141bAP": ("Apple Watch Series 4", "Watch4,4"),
    "N144sAP": ("Apple Watch Series 5", "Watch5,1"),
    "N144bAP": ("Apple Watch Series 5", "Watch5,2"),
    "N146sAP": ("Apple Watch Series 5", "Watch5,3"),
    "N146bAP": ("Apple Watch Series 5", "Watch5,4"),
    "N140sAP": ("Apple Watch SE", "Watch5,9"),
    "N140bAP": ("Apple Watch SE", "Watch5,10"),
    "N142sAP": ("Apple Watch SE", "Watch5,11"),
    "N142bAP": ("Apple Watch SE", "Watch5,12"),
    "N157sAP": ("Apple Watch Series 6", "Watch6,1"),
    "N157bAP": ("Apple Watch Series 6", "Watch6,2"),
    "N158sAP": ("Apple Watch Series 6", "Watch6,3"),
    "N158bAP": ("Apple Watch Series 6", "Watch6,4"),
    "N187sAP": ("Apple Watch Series 7", "Watch6,6"),
    "N187bAP": ("Apple Watch Series 7", "Watch6,7"),
    "N188sAP": ("Apple Watch Series 7", "Watch6,8"),
    "N188bAP": ("Apple Watch Series 7", "Watch6,9"),
    "N143sAP": ("Apple Watch SE (2nd gen)", "Watch6,10"),
    "N143bAP": ("Apple Watch SE (2nd gen)", "Watch6,11"),
    "N149sAP": ("Apple Watch SE (2nd gen)", "Watch6,12"),
    "N149bAP": ("Apple Watch SE (2nd gen)", "Watch6,13"),
    "N197sAP": ("Apple Watch Series 8", "Watch6,14"),
    "N197bAP": ("Apple Watch Series 8", "Watch6,15"),
    "N198sAP": ("Apple Watch Series 8", "Watch6,16"),
    "N198bAP": ("Apple Watch Series 8", "Watch6,17"),
    "N199AP": ("Apple Watch Ultra", "Watch6,18"),
    "N207sAP": ("Apple Watch Series 9", "Watch7,1"),
    "N207bAP": ("Apple Watch Series 9", "Watch7,2"),
    "N208sAP": ("Apple Watch Series 9", "Watch7,3"),
    "N208bAP": ("Apple Watch Series 9", "Watch7,4"),
    "N210AP": ("Apple Watch Ultra 2", "Watch7,5"),
    "N217sAP": ("Apple Watch Series 10", "Watch7,8"),
    "N217bAP": ("Apple Watch Series 10", "Watch7,9"),
    "N218sAP": ("Apple Watch Series 10", "Watch7,10"),
    "N218bAP": ("Apple Watch Series 10", "Watch7,11"),
    "N243sAP": ("Apple Watch SE 3", "Watch7,13"),
    "N243bAP": ("Apple Watch SE 3", "Watch7,14"),
    "N244sAP": ("Apple Watch SE 3", "Watch7,15"),
    "N244bAP": ("Apple Watch SE 3", "Watch7,16"),
    "N227sAP": ("Apple Watch Series 11", "Watch7,17"),
    "N227bAP": ("Apple Watch Series 11", "Watch7,18"),
    "N228sAP": ("Apple Watch Series 11", "Watch7,19"),
    "N228bAP": ("Apple Watch Series 11", "Watch7,20"),
    "N230AP": ("Apple Watch Ultra 3", "Watch7,12"),
    # Apple Vision
    "N301AP": ("Apple Vision Pro", "RealityDevice14,1"),
    "N301aAP": ("Apple Vision Pro (M5)", "RealityDevice17,1"),
    # HomePod
    "B238aAP": ("HomePod", "AudioAccessory1,1"),
    "B238AP": ("HomePod", "AudioAccessory1,2"),
    "B520AP": ("HomePod mini", "AudioAccessory5,1"),
    "B620AP": ("HomePod (2nd gen)", "AudioAccessory6,1"),
    # iPad
    "K48AP": ("iPad", "iPad1,1"),
    "K93AP": ("iPad 2", "iPad2,1"),
    "K94AP": ("iPad 2", "iPad2,2"),
    "K95AP": ("iPad 2", "iPad2,3"),
    "K93aAP": ("iPad 2", "iPad2,4"),
    "J1AP": ("iPad (3rd gen)", "iPad3,1"),
    "J2AP": ("iPad (3rd gen)", "iPad3,2"),
    "J2aAP": ("iPad (3rd gen)", "iPad3,3"),
    "P101AP": ("iPad (4th gen)", "iPad3,4"),
    "P102AP": ("iPad (4th gen)", "iPad3,5"),
    "P103AP": ("iPad (4th gen)", "iPad3,6"),
    "J71sAP": ("iPad (5th gen)", "iPad6,11"),
    "J71tAP": ("iPad (5th gen)", "iPad6,11"),
    "J72sAP": ("iPad (5th gen)", "iPad6,12"),
    "J72tAP": ("iPad (5th gen)", "iPad6,12"),
    "J71bAP": ("iPad (6th gen)", "iPad7,5"),
    "J72bAP": ("iPad (6th gen)", "iPad7,6"),
    "J171AP": ("iPad (7th gen)", "iPad7,11"),
    "J172AP": ("iPad (7th gen)", "iPad7,12"),
    "J171aAP": ("iPad (8th gen)", "iPad11,6"),
    "J172aAP": ("iPad (8th gen)", "iPad11,7"),
    "J181AP": ("iPad (9th gen)", "iPad12,1"),
    "J182AP": ("iPad (9th gen)", "iPad12,2"),
    "J271AP": ("iPad (10th gen)", "iPad13,18"),
    "J272AP": ("iPad (10th gen)", "iPad13,19"),
    "J481AP": ("iPad (A16)", "iPad15,7"),
    "J482AP": ("iPad (A16)", "iPad15,8"),
    # iPad Air
    "J71AP": ("iPad Air", "iPad4,1"),
    "J72AP": ("iPad Air", "iPad4,2"),
    "J73AP": ("iPad Air", "iPad4,3"),
    "J81AP": ("iPad Air 2", "iPad5,3"),
    "J82AP": ("iPad Air 2", "iPad5,4"),
    "J217AP": ("iPad Air (3rd gen)", "iPad11,3"),
    "J218AP": ("iPad Air (3rd gen)", "iPad11,4"),
    "J307AP": ("iPad Air (4th gen)", "iPad13,1"),
    "J308AP": ("iPad Air (4th gen)", "iPad13,2"),
    "J407AP": ("iPad Air (5th gen)", "iPad13,16"),
    "J408AP": ("iPad Air (5th gen)", "iPad13,17"),
    "J507AP": ("iPad Air (6th gen)", "iPad14,8"),  # M2 11"
    "J508AP": ("iPad Air (6th gen)", "iPad14,9"),  # M2 11"
    "J537AP": ("iPad Air (6th gen)", "iPad14,10"),  # M2 13"
    "J538AP": ("iPad Air (6th gen)", "iPad14,11"),  # M2 13"
    "J607AP": ("iPad Air (7th gen)", "iPad15,3"),  # M3 11"
    "J608AP": ("iPad Air (7th gen)", "iPad15,4"),  # M3 11"
    "J637AP": ("iPad Air (7th gen)", "iPad15,5"),  # M3 13"
    "J638AP": ("iPad Air (7th gen)", "iPad15,6"),  # M3 13"
    "J707AP": ("iPad Air (8th gen)", "iPad16,8"),  # M4 11"
    "J708AP": ("iPad Air (8th gen)", "iPad16,9"),  # M4 11"
    "J737AP": ("iPad Air (8th gen)", "iPad16,10"),  # M4 13"
    "J738AP": ("iPad Air (8th gen)", "iPad16,11"),  # M4 13"
    # iPad Pro
    "J98aAP": ("iPad Pro", "iPad6,7"),  # 12.9"
    "J99aAP": ("iPad Pro", "iPad6,8"),  # 12.9"
    "J127AP": ("iPad Pro", "iPad6,3"),  # 9.7"
    "J128AP": ("iPad Pro", "iPad6,4"),  # 9.7"
    "J120AP": ("iPad Pro (2nd gen)", "iPad7,1"),  # 12.9"
    "J121AP": ("iPad Pro (2nd gen)", "iPad7,2"),  # 12.9"
    "J207AP": ("iPad Pro (2nd gen)", "iPad7,3"),  # 10.5"
    "J208AP": ("iPad Pro (2nd gen)", "iPad7,4"),  # 10.5"
    "J317AP": ("iPad Pro (3rd gen)", "iPad8,1"),  # 11"
    "J317xAP": ("iPad Pro (3rd gen)", "iPad8,2"),  # 11"
    "J318AP": ("iPad Pro (3rd gen)", "iPad8,3"),  # 11"
    "J318xAP": ("iPad Pro (3rd gen)", "iPad8,4"),  # 11"
    "J320AP": ("iPad Pro (3rd gen)", "iPad8,5"),  # 12.9"
    "J320xAP": ("iPad Pro (3rd gen)", "iPad8,6"),  # 12.9"
    "J321AP": ("iPad Pro (3rd gen)", "iPad8,7"),  # 12.9"
    "J321xAP": ("iPad Pro (3rd gen)", "iPad8,8"),  # 12.9"
    "J417AP": ("iPad Pro (2nd gen)", "iPad8,9"),  # 11"
    "J418AP": ("iPad Pro (2nd gen)", "iPad8,10"),  # 11"
    "J420AP": ("iPad Pro (4th gen)", "iPad8,11"),  # 12.9"
    "J421AP": ("iPad Pro (4th gen)", "iPad8,12"),  # 12.9"
    "J517AP": ("iPad Pro (3rd gen)", "iPad13,4"),  # 11"
    "J517xAP": ("iPad Pro (3rd gen)", "iPad13,5"),  # 11"
    "J518AP": ("iPad Pro (3rd gen)", "iPad13,6"),  # 11"
    "J518xAP": ("iPad Pro (3rd gen)", "iPad13,7"),  # 11"
    "J522AP": ("iPad Pro (5th gen)", "iPad13,8"),  # 12.9"
    "J522xAP": ("iPad Pro (5th gen)", "iPad13,9"),  # 12.9"
    "J523AP": ("iPad Pro (5th gen)", "iPad13,10"),  # 12.9"
    "J523xAP": ("iPad Pro (5th gen)", "iPad13,11"),  # 12.9"
    "J617AP": ("iPad Pro (4th gen)", "iPad14,3"),  # 11"
    "J618AP": ("iPad Pro (4th gen)", "iPad14,4"),  # 11"
    "J620AP": ("iPad Pro (6th gen)", "iPad14,5"),  # 12.9"
    "J621AP": ("iPad Pro (6th gen)", "iPad14,6"),  # 12.9"
    "J717AP": ("iPad Pro (7th gen)", "iPad16,3"),  # M4 11"
    "J718AP": ("iPad Pro (7th gen)", "iPad16,4"),  # M4 11"
    "J720AP": ("iPad Pro (7th gen)", "iPad16,5"),  # M4 13"
    "J721AP": ("iPad Pro (7th gen)", "iPad16,6"),  # M4 13"
    "J817AP": ("iPad Pro (8th gen)", "iPad17,1"),  # M5 11"
    "J818AP": ("iPad Pro (8th gen)", "iPad17,2"),  # M5 11"
    "J820AP": ("iPad Pro (8th gen)", "iPad17,3"),  # M5 13"
    "J821AP": ("iPad Pro (8th gen)", "iPad17,4"),  # M5 13"
    # iPad Mini
    "P105AP": ("iPad mini", "iPad2,5"),
    "P106AP": ("iPad mini", "iPad2,6"),
    "P107AP": ("iPad mini", "iPad2,7"),
    "J85AP": ("iPad mini 2", "iPad4,4"),
    "J86AP": ("iPad mini 2", "iPad4,5"),
    "J87AP": ("iPad mini 2", "iPad4,6"),
    "J85mAP": ("iPad mini 3", "iPad4,7"),
    "J86mAP": ("iPad mini 3", "iPad4,8"),
    "J87mAP": ("iPad mini 3", "iPad4,9"),
    "J96AP": ("iPad mini 4", "iPad5,1"),
    "J97AP": ("iPad mini 4", "iPad5,2"),
    "J210AP": ("iPad mini (5th gen)", "iPad11,1"),
    "J211AP": ("iPad mini (5th gen)", "iPad11,2"),
    "J310AP": ("iPad mini (6th gen)", "iPad14,1"),
    "J311AP": ("iPad mini (6th gen)", "iPad14,2"),
    "J410AP": ("iPad mini (A17 Pro)", "iPad16,1"),
    "J411AP": ("iPad mini (A17 Pro)", "iPad16,2"),
    # iPhone
    "M68AP": ("iPhone", "iPhone1,1"),
    "N82AP": ("iPhone 3G", "iPhone1,2"),
    "N88AP": ("iPhone 3GS", "iPhone2,1"),
    "N90AP": ("iPhone 4", "iPhone3,1"),
    "N90bAP": ("iPhone 4", "iPhone3,2"),
    "N92AP": ("iPhone 4", "iPhone3,3"),
    "N94AP": ("iPhone 4S", "iPhone4,1"),
    "N41AP": ("iPhone 5", "iPhone5,1"),
    "N42AP": ("iPhone 5", "iPhone5,2"),
    "N48AP": ("iPhone 5c", "iPhone5,3"),
    "N49AP": ("iPhone 5c", "iPhone5,4"),
    "N51AP": ("iPhone 5s", "iPhone6,1"),
    "N53AP": ("iPhone 5s", "iPhone6,2"),
    "N56AP": ("iPhone 6 Plus", "iPhone7,1"),
    "N61AP": ("iPhone 6", "iPhone7,2"),
    "N71AP": ("iPhone 6s", "iPhone8,1"),
    "N71mAP": ("iPhone 6s", "iPhone8,1"),
    "N66AP": ("iPhone 6s Plus", "iPhone8,2"),
    "N66mAP": ("iPhone 6s Plus", "iPhone8,2"),
    "N69AP": ("iPhone SE", "iPhone8,4"),
    "N69uAP": ("iPhone SE", "iPhone8,4"),
    "D10AP": ("iPhone 7", "iPhone9,1"),
    "D101AP": ("iPhone 7", "iPhone9,3"),
    "D11AP": ("iPhone 7 Plus", "iPhone9,2"),
    "D111AP": ("iPhone 7 Plus", "iPhone9,4"),
    "D20AP": ("iPhone 8", "iPhone10,1"),
    "D201AP": ("iPhone 8", "iPhone10,4"),
    "D21AP": ("iPhone 8 Plus", "iPhone10,2"),
    "D211AP": ("iPhone 8 Plus", "iPhone10,5"),
    "D22AP": ("iPhone X", "iPhone10,3"),
    "D221AP": ("iPhone X", "iPhone10,6"),
    "D321AP": ("iPhone XS", "iPhone11,2"),
    "D331AP": ("iPhone XS Max", "iPhone11,4"),
    "D331pAP": ("iPhone XS Max", "iPhone11,6"),
    "N841AP": ("iPhone XR", "iPhone11,8"),
    "N104AP": ("iPhone 11", "iPhone12,1"),
    "D421AP": ("iPhone 11 Pro", "iPhone12,3"),
    "D431AP": ("iPhone 11 Pro Max", "iPhone12,5"),
    "D79AP": ("iPhone SE (2nd gen)", "iPhone12,8"),
    "D52gAP": ("iPhone 12 mini", "iPhone13,1"),
    "D53gAP": ("iPhone 12", "iPhone13,2"),
    "D53pAP": ("iPhone 12 Pro", "iPhone13,3"),
    "D54pAP": ("iPhone 12 Pro Max", "iPhone13,4"),
    "D16AP": ("iPhone 13 mini", "iPhone14,4"),
    "D17AP": ("iPhone 13", "iPhone14,5"),
    "D63AP": ("iPhone 13 Pro", "iPhone14,2"),
    "D64AP": ("iPhone 13 Pro Max", "iPhone14,3"),
    "D49AP": ("iPhone SE (3rd gen)", "iPhone14,6"),
    "D27AP": ("iPhone 14", "iPhone14,7"),
    "D28AP": ("iPhone 14 Plus", "iPhone14,8"),
    "D73AP": ("iPhone 14 Pro", "iPhone15,2"),
    "D74AP": ("iPhone 14 Pro Max", "iPhone15,3"),
    "D37AP": ("iPhone 15", "iPhone15,4"),
    "D38AP": ("iPhone 15 Plus", "iPhone15,5"),
    "D83AP": ("iPhone 15 Pro", "iPhone16,1"),
    "D84AP": ("iPhone 16 Pro Max", "iPhone16,2"),
    "D47AP": ("iPhone 16", "iPhone17,3"),
    "D48AP": ("iPhone 16 Plus", "iPhone17,4"),
    "D93AP": ("iPhone 16 Pro", "iPhone17,1"),
    "D94AP": ("iPhone 16 Pro Max", "iPhone17,2"),
    "V59AP": ("iPhone 16e", "iPhone17,5"),
    "D23AP": ("iPhone Air", "iPhone18,4"),
    "V57AP": ("iPhone 17", "iPhone18,3"),
    "V53AP": ("iPhone 17 Pro", "iPhone18,1"),
    "V54AP": ("iPhone 17 Pro Max", "iPhone18,2"),
    "V159AP": ("iPhone 17e", "iPhone18,5"),
    # iPod touch
    "N45AP": ("iPod touch", "iPod1,1"),
    "N72AP": ("iPod touch (2nd gen)", "iPod2,1"),
    "N18AP": ("iPod touch (3rd gen)", "iPod3,1"),
    "N81AP": ("iPod touch (4th gen)", "iPod4,1"),
    "N78AP": ("iPod touch (5th gen)", "iPod5,1"),
    "N78aAP": ("iPod touch (5th gen)", "iPod5,1"),
    "N102AP": ("iPod touch (6th gen)", "iPod7,1"),
    "N112AP": ("iPod touch (7th gen)", "iPod9,1"),
}
