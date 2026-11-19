#!/usr/bin/env python3
"""R-6 threads API battery (CI copy). Base URL from ATRIUM_BASE
(default http://127.0.0.1:5080). Expects the CI seed (tests/seed-ci.py):
users jdoe/asmith and channels 1-3; the server seeds the admin itself.
Covers the design record's Verify list: send validation matrix,
auto-follow, follow/unfollow, notification fan-out with mention
precedence, root-only channel unread, thread read positions, reply
counts excluding deleted, deleted-root behavior, reply edit/delete."""
import json, sys, urllib.request, urllib.error, http.cookiejar, uuid

BASE = __import__('os').environ.get('ATRIUM_BASE', 'http://127.0.0.1:5080')
results = []

def check(name, cond, extra=''):
    results.append((name, bool(cond)))
    print(('PASS' if cond else 'FAIL'), name, extra if not cond else '')

class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method,
                                     headers={'Content-Type': 'application/json'})
        try:
            with self.opener.open(req) as res:
                raw = res.read()
                status, payload = res.status, (json.loads(raw or b'null') if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                status, payload = e.code, json.loads(raw or b'null')
            except Exception:
                status, payload = e.code, {'raw': raw.decode('utf-8', 'replace')}
        for c in self.jar:
            c.secure = False  # Secure cookie over local http
        return status, payload

    def login(self, username, password):
        return self.call('POST', '/api/auth/login', {'username': username, 'password': password})

def send(client, channel, body, parent=None):
    payload = {'body': body, 'clientGuid': str(uuid.uuid4())}
    if parent is not None:
        payload['parentId'] = parent
    return client.call('POST', f'/api/channels/{channel}/messages', payload)

admin = Client()
st, _ = admin.login('admin', 'ChangeMe!2026')
if st != 200:
    st, _ = admin.login('admin', 'BrandNew!2026x')
st, me = admin.call('GET', '/api/me')
if me and me.get('mustChangePassword'):
    st, _ = admin.call('POST', '/api/auth/change-password',
                       {'currentPassword': 'ChangeMe!2026', 'newPassword': 'BrandNew!2026x'})
    check('admin password rotation', st == 200, f'status {st}')
jdoe = Client(); st, _ = jdoe.login('jdoe', 'Password!2026'); check('jdoe login', st == 200, f'{st}')
asmith = Client(); st, _ = asmith.login('asmith', 'Password!2026'); check('asmith login', st == 200, f'{st}')

GEN, HELP = 1, 2
# asmith must be a member of #general for the fan-out checks
admin.call('POST', f'/api/channels/{GEN}/members', {'username': 'asmith'})

# --- root + reply happy path ---
st, root = send(jdoe, GEN, 'battery thread root')
check('root send', st == 200, f'{st} {root}')
root_id, root_seq = root['id'], root['seq']
st, reply1 = send(asmith, GEN, 'battery first reply')
check('reply without parent is a root (control)', st == 200 and reply1.get('parentId') is None)
# remove the control message from the thread math by deleting it
jdoe.call('DELETE', f'/api/channels/{GEN}/messages/{reply1["seq"]}')
st, reply1 = send(asmith, GEN, 'battery first reply', parent=root_id)
check('reply send', st == 200 and reply1.get('parentId') == root_id, f'{st} {reply1}')
reply1_seq = reply1['seq']

# --- validation matrix ---
st, r = send(jdoe, GEN, 'nested reply attempt', parent=reply1['id'])
check('nested reply refused 400', st == 400 and 'one level deep' in r.get('error', ''), f'{st} {r}')
st, r = send(jdoe, HELP, 'cross channel parent', parent=root_id)
check('cross-channel parent refused 400', st == 400, f'{st} {r}')
st, r = send(jdoe, GEN, 'ghost parent', parent=999999)
check('missing parent refused 400', st == 400, f'{st} {r}')
st, r = send(asmith, GEN, 'emoji reply 😀', parent=root_id)
check('emoji reply refused 400', st == 400, f'{st} {r}')

# --- list shape: roots only + aggregates ---
st, msgs = jdoe.call('GET', f'/api/channels/{GEN}/messages?limit=50')
roots = [m for m in msgs if m['seq'] == root_seq]
check('channel list contains the root', len(roots) == 1)
check('channel list excludes replies', all(m.get('parentId') is None for m in msgs))
check('root replyCount = 1', roots and roots[0]['replyCount'] == 1, f'{roots}')
check('root lastReplyAt set', roots and roots[0]['lastReplyAt'] is not None)
check('root hasUnreadReplies for non-author', roots and roots[0]['hasUnreadReplies'] is True)
check('root not followed by jdoe yet', roots and roots[0]['followedByMe'] is False)

st, msgs_a = asmith.call('GET', f'/api/channels/{GEN}/messages?limit=50')
roots_a = [m for m in msgs_a if m['seq'] == root_seq]
check('replier auto-follows (followedByMe)', roots_a and roots_a[0]['followedByMe'] is True)

# --- channel unread is roots-only ---
st, chans = jdoe.call('GET', '/api/channels')
unread_before = [c for c in chans if c['id'] == GEN][0]['unread']
st, reply2 = send(asmith, GEN, 'battery second reply', parent=root_id)
st, chans = jdoe.call('GET', '/api/channels')
unread_after = [c for c in chans if c['id'] == GEN][0]['unread']
check('channel unread unchanged by replies', unread_before == unread_after,
      f'{unread_before} -> {unread_after}')

# --- thread GET + read positions ---
st, thread = jdoe.call('GET', f'/api/channels/{GEN}/threads/{root_seq}')
check('thread GET root + replies', st == 200 and thread['root']['seq'] == root_seq
      and len(thread['replies']) == 2, f'{st} {thread and len(thread.get("replies", []))}')
check('thread GET rootId matches', thread['rootId'] == root_id)
st, _ = jdoe.call('POST', f'/api/channels/{GEN}/threads/{root_seq}/read', {'seq': reply2['seq']})
check('mark thread read', st == 200, f'{st}')
st, msgs = jdoe.call('GET', f'/api/channels/{GEN}/messages?limit=50')
roots = [m for m in msgs if m['seq'] == root_seq]
check('hasUnreadReplies cleared after read', roots and roots[0]['hasUnreadReplies'] is False)
st, _ = jdoe.call('POST', f'/api/channels/{GEN}/threads/{root_seq}/read', {'seq': 1})
st, thread = jdoe.call('GET', f'/api/channels/{GEN}/threads/{root_seq}')
check('read position never moves backwards', thread['lastReadSeq'] == reply2['seq'],
      f"{thread['lastReadSeq']} vs {reply2['seq']}")

# --- follow / unfollow endpoints ---
st, _ = jdoe.call('POST', f'/api/channels/{GEN}/threads/{root_seq}/follow')
st, thread = jdoe.call('GET', f'/api/channels/{GEN}/threads/{root_seq}')
check('follow endpoint', st == 200 and thread['followedByMe'] is True)
st, _ = jdoe.call('DELETE', f'/api/channels/{GEN}/threads/{root_seq}/follow')
st, thread = jdoe.call('GET', f'/api/channels/{GEN}/threads/{root_seq}')
check('unfollow endpoint', st == 200 and thread['followedByMe'] is False)
# jdoe follows again for the fan-out checks below
jdoe.call('POST', f'/api/channels/{GEN}/threads/{root_seq}/follow')

# --- notification fan-out ---
def notif_count(client):
    st, n = client.call('GET', '/api/notifications?limit=100')
    return len([i for i in n['items'] if i.get('target') == f'thread:{GEN}:{root_seq}']), n['items']

admin_before, _ = notif_count(admin)
asmith_before, _ = notif_count(asmith)
st, reply3 = send(jdoe, GEN, 'battery third reply', parent=root_id)
asmith_after, items = notif_count(asmith)
admin_after, _ = notif_count(admin)
mine = [i for i in items if i.get('target') == f'thread:{GEN}:{root_seq}']
check('follower notified of reply', asmith_after == asmith_before + 1, f'{asmith_before} -> {asmith_after}')
check('thread notification kind is channel', mine and mine[0]['kind'] == 'channel', f'{mine[:1]}')
check('non-follower member not notified', admin_after == admin_before, f'{admin_before} -> {admin_after}')
st, reply4 = send(jdoe, GEN, 'battery mention @asmith in thread', parent=root_id)
_, items = notif_count(asmith)
mentions = [i for i in items if i.get('target') == f'thread:{GEN}:{root_seq}' and i['kind'] == 'mention']
check('mention in reply yields one mention notification', len(mentions) == 1, f'{len(mentions)}')

# --- edit + delete a reply ---
st, edited = asmith.call('PUT', f'/api/channels/{GEN}/messages/{reply1_seq}', {'body': 'battery first reply edited'})
check('reply edit by author', st == 200 and edited['body'].endswith('edited'), f'{st} {edited}')
st, thread = jdoe.call('GET', f'/api/channels/{GEN}/threads/{root_seq}')
check('thread shows edited reply', any(r['seq'] == reply1_seq and r['body'].endswith('edited') for r in thread['replies']))
st, _ = asmith.call('DELETE', f'/api/channels/{GEN}/messages/{reply2["seq"]}')
check('reply delete by author', st == 200, f'{st}')
st, thread = jdoe.call('GET', f'/api/channels/{GEN}/threads/{root_seq}')
check('deleted reply gone from thread', all(r['seq'] != reply2['seq'] for r in thread['replies']))
st, msgs = jdoe.call('GET', f'/api/channels/{GEN}/messages?limit=50')
roots = [m for m in msgs if m['seq'] == root_seq]
check('replyCount excludes deleted replies', roots and roots[0]['replyCount'] == 3, f'{roots}')

# --- search carries the thread anchor ---
st, found = jdoe.call('GET', '/api/search?q=' + urllib.parse.quote('mention @asmith in thread') if False else '/api/search?q=battery%20mention')
items = found['items'] if st == 200 else []
hit = [i for i in items if i['seq'] == reply4['seq']]
check('search finds the reply with parentId + rootSeq',
      bool(hit) and hit[0]['parentId'] == root_id and hit[0]['rootSeq'] == root_seq, f'{hit}')

# --- membership gate on thread endpoints ---
st, priv = admin.call('POST', '/api/channels', {'name': 'battery-private'})
priv_id = priv['id']
st, proot = send(admin, priv_id, 'private root')
st, r = asmith.call('GET', f'/api/channels/{priv_id}/threads/{proot["seq"]}')
check('non-member thread GET is 403', st == 403, f'{st}')

# --- deleted root: thread survives, replies stay, new replies refused ---
st, _ = jdoe.call('DELETE', f'/api/channels/{GEN}/messages/{root_seq}')
check('root delete by author', st == 200, f'{st}')
st, thread = asmith.call('GET', f'/api/channels/{GEN}/threads/{root_seq}')
check('deleted root reads back null with replies intact',
      st == 200 and thread['root'] is None and len(thread['replies']) == 3,
      f"{st} root={thread.get('root')} replies={len(thread.get('replies', []))}")
st, msgs = asmith.call('GET', f'/api/channels/{GEN}/messages?limit=50')
check('deleted root absent from channel list', all(m['seq'] != root_seq for m in msgs))
st, r = send(asmith, GEN, 'reply to deleted root', parent=root_id)
check('reply to deleted root refused 400', st == 400 and 'deleted' in r.get('error', ''), f'{st} {r}')
st, r = asmith.call('GET', f'/api/channels/{GEN}/threads/999999')
check('unknown thread is 404', st == 404, f'{st}')

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} PASS")
if failed:
    print('FAILED:', failed); sys.exit(1)
