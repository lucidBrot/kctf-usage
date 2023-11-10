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
  * set the filesystem permissions in `nsjail.cfg` to `rw: true`
  * specify it correctly in `challenge.yaml` as well, see [this kctf github issue](https://github.com/google/kctf/issues/388#issuecomment-1335660783) for an example where exactly to specify this. It is in `spec.podTemplate.template.spec.containers.securityContext`.
  * Sometimes it seemed to me that I also needed `privileged: true` when it complained about readonly filesystem.

## run a kctf challenge without kubernetes

`kctf`  has an option to simulate a local "kind" kubernetes cluster. But you can also just launch your docker almost normally. It will usually need `--privileged`, but that is okay because the docker is not what is ensuring the security anyway.

```bash
docker build -t myimage .
docker run --privileged -p1337:1337 -it myimage
```

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