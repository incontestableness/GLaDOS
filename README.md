# GLaDOS


## What is GLaDOS?

GLaDOS is a centralized server for:
* receiving [hathook](https://github.com/incontestableness/hathook-public) bot events via [portalgun](https://github.com/incontestableness/portalgun)
* controlling hathook anti-bot map queueing to more efficiently target malicious bots
* providing an API for aggregated statistics

GLaDOS also enables users running [hathook](https://github.com/incontestableness/hathook-public) to automatically abandon matches with malicious bots in them without having to join the server first. Similarly, hathook bots also take advantage of this functionality to avoid joining matches that don't have malicious bots.

GLaDOS relies on per-region lists of TF2 servers to scan in order to provide the map targeting functionality. These can be most efficiently curated with **potato.py**.


## What's zeolite.py?

Zeolite was the first method I tried for TF2 server discovery. It scans all of Valve's server ranges for TF2 servers. It's unreliable for some regions and thus requires several attempts at scanning. Shortly after finishing it I came across the Steam API that potato.py uses. The code's just here for looks. Please don't use it.


## What's potato.py?

After writing zeolite.py, I found that an API endpoint Steam makes available allows you to get a list of servers running on a given IP address. [This approach is a lot less complex and much more efficient.](https://i1.theportalwiki.net/img/5/58/GLaDOS_potatos_longfall_speech03.wav) It only takes about 10 minutes to scan regions known to host TF2 dedicated servers.

However, the API sometimes does not return information on servers that ought to be running on a port, presumably because they were offline at the time. To solve this, potato.py adds to the lists with subsequent runs. This has the consequence that if an IP address no longer hosts servers, this will not be reflected in the lists until they are deleted and repopulated.


## How do I use this?

**You don't need to run your own instance of GLaDOS.** A server is already hosted and configured as the default in [portalgun](https://github.com/incontestableness/portalgun).

Simply run a local instance of [portalgun](https://github.com/incontestableness/portalgun) and your [hathook](https://github.com/incontestableness/hathook-public) installation should work as intended.

**It is strongly recommended that you use the default central server as GLaDOS takes up considerable network bandwidth when scanning TF2 servers to target bot maps.**


## Why did you do this?

1. In order to enable hosting anti-bots in multiple regions while still gathering aggregated statistics easily
2. Much more efficient targeting of matches with malicious bots
3. Provide for a better [hathook](https://github.com/incontestableness/hathook-public) user experience
4. Create an API that enables displaying statistics on [the website](https://milenko-tf2.github.io/)
5. Science is fun


## Why the name?

["It's funny, actually, when you think about it."](https://i1.theportalwiki.net/img/3/3b/GLaDOS_escape_01_part1_nag09-1.wav) - Potato GLaDOS
