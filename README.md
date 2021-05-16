# GLaDOS

![Who are you?](https://i.imgur.com/0gbb1AH.png)


## What is GLaDOS?

GLaDOS is a centralized server for:
* receiving [hathook](https://github.com/incontestableness/hathook-public) bot events via [portalgun](https://github.com/incontestableness/portalgun)
* controlling hathook anti-bot map queueing to more efficiently target malicious bots
* providing an API for aggregated statistics

GLaDOS also enables users running [hathook](https://github.com/incontestableness/hathook-public) to automatically abandon matches with malicious bots in them without having to join the server first. Similarly, hathook bots also take advantage of this functionality to avoid joining matches that don't have malicious bots.

GLaDOS relies on per-region lists of TF2 servers to scan in order to provide the map targeting functionality. These can be most efficiently curated with **potato.py**.


## What's zeolite.py?

Zeolite was the first method Milenko tried for TF2 server discovery. It scans all of Valve's server ranges for TF2 servers. It's unreliable for some regions and thus requires several attempts at scanning. Shortly after finishing it he came across the Steam API that potato.py uses. The code's just here for looks.

"yeah zeolite sucks don't use it" - The Great Milenko, 04/10/2021


## What's potato.py?

After writing zeolite.py, Milenko found that an API endpoint Steam makes available allows you to get a list of servers running on a given IP address. [This approach is a lot less complex and much more efficient.](https://i1.theportalwiki.net/img/5/58/GLaDOS_potatos_longfall_speech03.wav) It only takes about 5 minutes to scan regions known to host TF2 dedicated servers.


## How do I use this?

**You don't need to run your own instance of GLaDOS.** A server is already hosted and configured as the default in [portalgun](https://github.com/incontestableness/portalgun).

Simply run a local instance of [portalgun](https://github.com/incontestableness/portalgun) and your [hathook](https://github.com/incontestableness/hathook-public) installation should work as intended.

**It is strongly recommended that you use the default central server as GLaDOS takes up considerable network bandwidth when scanning TF2 servers to target bot maps.**

If you you want to contribute, check out todo.txt.


## Is the GLaDOS API publicly available?

Yes! You can access the API at http://milenko.ml/api/something where "/something" is the relevant API call.

All responses are returned in JSON format, unless an error is encountered. Most calls are limited to 10 or 20 requests per minute.

Here are the publicly available API calls:
* [/popmaps/region](http://milenko.ml/api/popmaps/iad) - A list of the most popular maps for malicious bots. See regions.txt for available regions.
* [/botnames](http://milenko.ml/api/botnames) - A list of potential bot names, based on multiple players using the same name.
* [/namerules](http://milenko.ml/api/namerules) - An auto-updating [TF2BD](https://github.com/PazerOP/tf2_bot_detector)-compatible rules list for current bot names.
* [/check/server](http://milenko.ml/api/check/208.78.165.231:27015) - The number of bots on the server and a list of likely namestealers.
* [/stats](http://milenko.ml/api/stats) - Cumulative statistics, updated every minute.


## Why did you do this?

1. In order to enable hosting anti-bots in multiple regions while still gathering aggregated statistics easily
2. Much more efficient targeting of matches with malicious bots
3. Provide for a better [hathook](https://github.com/incontestableness/hathook-public) user experience
4. Create an API that enables displaying statistics on [the website](http://milenko.ml/)
5. Science is fun


## Why the name?

["It's funny, actually, when you think about it."](https://i1.theportalwiki.net/img/3/3b/GLaDOS_escape_01_part1_nag09-1.wav) - Potato GLaDOS
