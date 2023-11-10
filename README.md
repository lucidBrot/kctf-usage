# kctf Usage

kctf is a script that uses [nsjail](https://github.com/google/nsjail/blob/master/config.proto) inside a docker container, which are launched in kubernetes. The nsjail is for security/isolation, the docker is for easy setup, kubernetes is for scaling, and `kctf` is a wrapper that launches all of that on google cloud.

There are some basic examples in the [kctf repo](https://github.com/google/kctf/tree/v1/dist/challenge-templates) and more advanced examples in [googlectf quals](https://github.com/google/google-ctf/tree/master/2022/quals/sandbox-ipcz). The official [walkthrough](https://google.github.io/kctf/google-cloud.html) explains how to set kctf up and launch it.

kctf clearly was made for simple pwn chals in mind that operate on stdin/stdout.
For any ... more interesting challenges, kctf can be a lot of work.

This document contains abstractions of what i learned struggling with it, and it will hopefully grow if I find the time for more additions.

## kctf-ify an existing challenge

You already have a docker that runs your ctf challenge, and want to use it in kctf?

* Ensure you do not need state beyond one tcp connection, because kctf might launch multiple docker instances for load-balancing and nsjail will not allow any second tcp connection to the same *jail instance* of the challenge.
* If you want to write to the filesystem, that can be enabled, but must be done explicitly, otherwise kubernetes will just default to non-writeable filesystem.
  * set the filesystem permissions in `nsjail.cfg` to `rw: true` if you want the challenge to modify the filesystem ... but usually you don't want that, and should instead mount tmpfs filesystems. But sometimes you might need this in order to even be able to create the tmpfs mountpoint... so, good to know.
  * specify it correctly in `challenge.yaml` as well, see [this kctf github issue](https://github.com/google/kctf/issues/388#issuecomment-1335660783) for an example where exactly to specify this. It is in `spec.podTemplate.template.spec.containers.securityContext`.
  * Sometimes it seemed to me that I also needed `privileged: true` when it complained about readonly filesystem.

Aside from those worries, you will also need to have kctf-related scripts and nsjail in the docker. The easiest ways to do so is to give your currently built stage a name in the Dockerfile (see [docker multistage builds](https://docs.docker.com/build/building/multi-stage/)) and then start a new final stage where you copy everything over to the image the kctf examples use, e.g. the [pwn example](https://github.com/google/kctf/blob/v1/dist/challenge-templates/pwn/challenge/Dockerfile#L23). Or take the latest from `gcr.io/kctf-docker/challenge`, i guess.

```Dockerfile
FROM some_image as chroot
# your challenge dockerfile stuff here.

FROM gcr.io/kctf-docker/challenge@sha256:eb0f8c3b97460335f9820732a42702c2fa368f7d121a671c618b45bbeeadab28 as kctfstage
COPY --from=chroot / /chroot
COPY nsjail.cfg /home/user
CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/chal"
```

In this, the `nsjail` launches the challenge binary at `/home/user/chal` . You might wonder "But the `chal` binary is *actually* at `/chroot/home/user/chal`?!".  That is true, but the `nsjail.cfg` contains a [config](https://github.com/google/kctf/blob/v1/dist/challenge-templates/pwn/challenge/nsjail.cfg#L32) that mounts the `/chroot` (as seen from the docker container perspective) to `/` (as seen from inside the nsjail).

```
mount: [
  {
    src: "/chroot"
    dst: "/"
    is_bind: true
  },

```

If you later want to only build the initial docker you had at the start, you can do so using

```
docker build --target chroot .
```

To run the newly created kctf-stage docker, you will have to use `--privileged`, lest you get "permission denied":

```bash
docker run --privileged -p 1337:1337 -it $(docker build -q --target kctf-stage .) 
```

## receive TCP traffic on port instead of stdin

The `socat` line in the `CMD` of the example. listens on port 1337 and launches an nsjail instance every time a connection comes in (thanks to `fork`, otherwise it would only take one connection). 

The communication then goes through the nsjail's stdin. 
Inside the nsjail, we want to do the opposite, as per [this web example](https://github.com/google/kctf/blob/v1/dist/challenge-templates/web/challenge/web-servers/nodejs.sh). Note that this relies on `/dev/null`, so the [nsjail.cfg](https://github.com/google/kctf/blob/v1/dist/challenge-templates/web/challenge/web-servers.nsjail.cfg#L36) now needs to mount `/dev` and `/dev/null`.

To do this, I create a script `unsocat.sh` that launches my server and then feeds stdin to the port 1337 it is listening on, and the output from it to stdout again. Which in turn gets fed through the nsjail layer to the client.

```bash
#!/bin/bash
# unsocat.sh: This script maps stdin to a tcp port and the output from there back to stdout.

# But first, let's launch our server.
# This is the same command as I would use as docker CMD if I were not using nsjail/kctf.
# But:
#   * in the background, thanks to the "&" at the end.
#   * not printing output, thanks to the &>/dev/null redirect. Leave it out for debugging.
(python3 /chal/chalspecific_server.py ) &

#echo "Debug: Server Launched."

# Now connect to it, without buffering.
# Ensure that the option is installed inside the chroot.
# Option 1: 
#stdbuf -o0 -i0 nc "127.0.0.1" 1337
# Option 2: socat has the "forever" option to retry until it works.
stdbuf -o0 -i0 socat - "TCP:127.0.0.1:1337,forever"

#echo "Debug: Done."
```

In the Dockerfile, I execute this script now instead of my server directly:

```Dockerfile
# So far so good. Now let's put that into kctf and nsjail.
FROM gcr.io/kctf-docker/challenge@sha256:eb0f8c3b97460335f9820732a42702c2fa368f7d121a671c618b45bbeeadab28 as kctf-stage
COPY --from=chal / /chroot
RUN mkdir /chroot/kctf
COPY --chmod=555 unsocat.sh /chroot/kctf/
COPY --chmod=444 nsjail.cfg /kctf/nsjail.cfg
RUN echo "127.0.0.1 NSJAIL" >> /chroot/etc/hosts

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /kctf/nsjail.cfg -- /kctf/unsocat.sh"
```

Also, my challenge would normally listen on `hostname:port`. But now, it seems the hostname is `NSJAIL` and does not resolve... so we need to add that to the `/etc/hosts` file. i do this with the line `RUN echo "127.0.0.1 NSJAIL" >> /chroot/etc/hosts` in my Dockerfile's final stage.

## run a kctf challenge without kubernetes

`kctf`  has an option to simulate a local "kind" kubernetes cluster. But you can also just launch your docker almost normally. It will usually need `--privileged`, but that is okay because the docker is not what is ensuring the security anyway.

```bash
docker build -t myimage .
docker run --privileged -p1337:1337 -it myimage
```

This is nice for a small deployment with few anticipated users, as it still has nsjail but no scaling kubernetes stuff.

But if you are planning to eventually use kubernetes for the CTF event, then please do first test it at least in kind, if not on the cloud already. I had the experience that GKE and Kind behave differently. E.g. I can access one challenge from another using kind, but not GKE.

## debug stuff inside nsjail

You can specify `/bin/bash` as the command that nsjail launches. This allows you to connect to it and look around, run the commands you need to run, see how they fail.

### Read-Only File System

If you get this without even touching the `kctf` command, just by running the docker, it is not because of kubernetes but because of nsjail (probably).

Connecting over netcat as usual, but with the nsjail command launching `/bin/bash`, we can explore the filesystem *inside* the jail. But even though the permissions look fine, doing `echo asdf > test.txt` makes the output of the nsjail docker terminal show `bin/bash: line 10: test.txt: Read-only file system`. The culprit is likely seen in the `nsjail.cfg`: In my case, I have mounted `/chroot` to `/` inside the jail, as a [bind mount](https://unix.stackexchange.com/questions/198590/what-is-a-bind-mount).

```
mount {
    src: "/chroot"
    dst: "/"
    is_bind: true
  }
```

I could add `rw: true` to make it writable, but then it would modify the files on disk also for new instances of the challenge. So instead, you might want to use a tmpfs for the writable files instead -- one tmpfs per jail instance:

```
mount {
     dst: "/tmp"
     fstype: "tmpfs"
     rw: true
}
```

Perhaps you might also get an [OverlayFS](https://askubuntu.com/questions/699565/example-overlayfs-usage) to work, but considering that that needs a tmpfs to store the changes in anyway, you might as well just stick with a copy of the original folder.

#### Making an OverlayFS (Not successful yet)

The option [X-mount.mkdir](https://unix.stackexchange.com/a/635263/66736) seems ideal to have the mount command create the missing mount points for us, but it does not work ("Invalid argument").

Without it, we need some pre-existing directories we can use in the overlay mount command (upperdir, lowerdir, workdir). And upperdir and workdir must be on the same filesystem to allow for atomic writing... so we must have a writable tmpfs and create two directories on it somehow. Otherwise, this config fails:

```
# using a tmpfs i can make an overlayfs to avoid copying
# a large pre-made folder. I don't have any large folders,
# but I am curious whether I can make it work.
# 
# https://github.com/google/nsjail states:
#   --mount|-m VALUE
# 	Arbitrary mount, format src:dst:fs_type:options

mount [
  {
    dst: "/tmp"
    fstype: "tmpfs"
    rw: true
  },
  {
    fstype: "overlay"
    options: "lowerdir=/chal,upperdir=/tmp/chal_upper,workdir=/tmp/chal_work"
    dst: "/tmp/chal"
  }
]
```

We can not create these missing directories in advance, since the filesystem outside the nsjail is not supposed to be writable from inside. But well, i guess we can make an exception this time ... We have to create a tmpfs before launching nsjail *every time socat receives a connection* (give it some randomized name), create the upperdir and workdir as empty folders inside it, and then pass that name to the nsjail command using the [command line flag](https://github.com/google/nsjail) `--bindmount "$NAMEHERE":/tmp2`.

But that fails with the warning

```
[W][2023-11-10T19:38:06+0000][1] remountPt():283 mount('/tmp2', flags:MS_REMOUNT|MS_BIND|MS_RELATIME): Invalid argument
```

If this happens to you, you have perhaps written something like this:

```bash
kctf_pow nsjail --bindmount "${mytmpfs}:/tmp2" --config /kctf/nsjail.cfg -- /bin/bash
```

If you change the order to the following, it works:

```bash
kctf_pow nsjail  --config /kctf/nsjail.cfg --bindmount "${mytmpfs}:/tmp2" -- /bin/bash
```

The `--config` apparently must come first. Probably due to the mounting of `/` in the config that comes too late otherwise? But well, this now also means that we must specify the overlay mount command itself in the command line here instead of the config. So something like this *should* work in my opinion, but it **does not work** and I'm not sure what is missing:

```bash
#!/bin/bash
set -x
mytmpfs=$(mktemp -d)
# if something fails, try to cleanup before exiting
function onexit {
    rm -r "$mytmpfs"
}
trap onexit EXIT
mkdir "${mytmpfs}/upperdir"
mkdir "${mytmpfs}/workdir"
TMP_INSIDE="/tmp"
TMP_OUTSIDE="$mytmpfs"
kctf_pow nsjail --config /kctf/nsjail.cfg  --bindmount "${mytmpfs}:${TMP_INSIDE}" --mount ":/chal:overlay:lowerdir=/chal,upperdir=${TMP_INSIDE}/upperdir,workdir=${TMP_INSIDE}/workdir" -- /bin/bash
```

```
[W][2023-11-10T20:41:52+0000][1] mountPt():223 mount(''/chal' flags: type:'overlay' options:'lowerdir=/chal,upperdir=/tmp/upperdir,workdir=/tmp/workdir' dir:true') src:'none' dstpath:'/tmp/nsjail.1000.root//chal' failed: No such file or directory
[E][2023-11-10T20:41:52+0000][1] initCloneNs():414 Couldn't mount '/chal'
```

I might return later to this, but for now I will use copies instead. :(

## allow network access from the jail to the outside

In general, `nsjail` makes networking impossible for the jailed challenge, except for the one incoming tcp connection that you get in through stdin. Suppose you have a challenge where the ctf player wants to launch a connection to a server on the internet. How to do that?

Well, that was a huge pain to get working. My notes are a huge jumble and the challenge where I implemented this is still secret. But if you need to do this, let me know and I'll try to read myself back into it to make better notes here.

See also [my confused answer attempt on serverfault](https://serverfault.com/questions/1013911/nsjail-process-does-not-have-network-access) back before I fully succeeded at it. And after I succeeded:

> I managed to make outgoing network access work for a dynamic number of jails and without requiring one LAN ip address per jail. I did so using veth pairs and masquerading. I hope I will find time to write up how to do so once I have thoroughly tested it 

The basic idea was to give every nsjail instance inside the docker a veth pair that allows connecting from inside the jail to outside, and then there using masquerading to get the request to the internet and back. This will also needs routing setup.

## get sudo to work inside nsjail

This was surprisingly tricky. The hardest of the issues to figure out is probably the one about needing a user with id `1` in the jail. It must not be the current user... but it must exist. Here's a paste from my notes:

To summarize the points I was stuck at in case someone needs sudo as well in kctf inside the nsjail jail:

* make sure the sudoers file is inside the jail, not only outside lmao

* make sure all groups and uids actually exist inside the jail. An invalid uid/gid can make it fail

* make sure all permissions of sudo and its library are correct. It must be owned by the user who is considered root inside the jail

* if you `chown`ed the sudo files, keep in mind that this will have removed the setuid bit from them, you need to re-add them

* all sudo-able uids/gids need to be mapped in the nsjail config to some valid outside uid/gid (not 100% sure that is necessary actually, if that user does not own any files). To do so for multiple users requires `use_newidmap: true` syntax inside the list of uid mappings, and a file `/etc/subuid` resp. `/etc/subgid` _outside_ the jail. The nsjail config syntax is rough to get right.

* the uid `1` _must_ exist inside the jail and be mapped to something valid outside the jail, otherwise the kernel gets confused and refuses the hackaround that sudo is trying to do to avoid some problem I do not understand, from 13 years ago

* there must be the necessary privileges granted in the nsjail config. Maybe I can still make this stricter, but for now I have `disable_no_new_privs: true` and `keep_caps: true`. (Likely it will be enough to say `cap: [ "CAP_SETFCAP", "CAP_SETUID", "CAP_SETGID" ]` instead of `keep_caps: true`. Notice that all  are needed.)

* It is not necessary to map the root user inside to the root user outside if you do a chown + set chmod with suid bit again.

* if you need to debug sudo, you can enable logging like this:

  ```
  # set up logging for real sudo
  RUN echo "Debug sudo /tmp/log_sudo all@debug\nDebug sudoers.so /tmp/log_sudoers all@debug\n" >> /etc/sudo.conf
  ```

Luckily my poc setup for getting sudo to run in nsjail (I have not yet run it inside the kctf kind cluster btw, that could still fail lol) is separate from my challenge, so if anyone needs to use sudo i guess it's easiest to just borrow my poc settings to see how the syntax works.

* My poc is based on ubuntu 18
* basing the chroot on python-alpine fails with new errors. Not recommendable.
* the python-slim and python base images seem to have locked the root account, so sudo fails when run as root.

## expose multiple ports

The easiest way to deal with this is to redesign the challenge. The second easiest way is to make the challenge contain a "jumpbox" shell from where the ctf player can operate. Because, well... there is just no way in kctf to reliably get traffic to the same instance through different tcp connections. And even if you do, it would then not reach the nsjail instance, unless you decided to go without nsjail.

But for some reason, [it is configurable anyway](https://github.com/google/kctf/tree/v1/dist/challenge-templates/pwn#challengeyaml), so maybe i am wrong.

