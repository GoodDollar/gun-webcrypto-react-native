import WebviewCrypto from 'react-native-webview-crypto';
import 'react-native-get-random-values';
import React, {useState, useEffect} from 'react';
import {
  StyleSheet,
  Text,
  View,
  Button,
  AsyncStorage,
  TextInput,
} from 'react-native';
import Gun from 'gun/gun';
import SEA from 'gun/sea';
import 'gun/lib/radix.js';
import 'gun/lib/radisk.js';
import 'gun/lib/store.js';
import Store from 'gun/lib/ras.js';

//rad asyncstorage adapter, on Android asyncstorage has 6mb limit by default
const asyncStore = Store({AsyncStorage});
let gun = Gun({
  peers: ['https://mvp-gun.herokuapp.com/gun'],
  store: asyncStore,
});
const timer = () => {
  let current = Date.now();
  return () => {
    const res = `${(Date.now() - current) / 1000} seconds`;
    current = Date.now();
    return res;
  };
};
export default function App() {
  let [state, setState] = useState({
    decrypted: '',
    pair: '',
    random: '',
    userCreated: false,
    user: '',
  });
  let [loginStatus, setLoginStatus] = useState({});
  let [uname, setUserName] = useState();
  let [pass, setPass] = useState();
  let [peer, setPeer] = useState('https://mvp-gun.herokuapp.com/gun');

  const clearStorage = () => {
    AsyncStorage.clear();
  };

  const restartGun = () => {
    gun = Gun({
      peers: [peer],
      store: asyncStore,
    });
  };
  const runTests = async () => {
    try {
      console.log('running tests', Gun, crypto);

      crypto.subtle
        .generateKey(
          {
            name: 'ECDSA',
            namedCurve: 'P-256', //can be "P-256", "P-384", or "P-521"
          },
          true, //whether the key is extractable (i.e. can be used in exportKey)
          ['sign', 'verify'], //can be any combination of "sign" and "verify"
        )
        .then(function(key) {
          //returns a keypair object
          console.log(key);
          console.log(key.publicKey);
          console.log(key.privateKey);
        })
        .catch(function(err) {
          console.error(err);
        });
      await test();
      await test2();
      await testTypes();
    } catch (e) {
      console.log('Test failed', e);
    }
  };

  const createUser = () =>
    new Promise((resolve, reject) => {
      console.log('start login');

      gun.user().create(uname, pass, r => {
        console.log('Gun user created result:', r);
        resolve(true);
        //setState(prev => ({...prev, userCreated: 'true'}));
      });
    });

  const authUser = () =>
    new Promise((resolve, reject) => {
      gun.user().auth(uname, pass, async userres => {
        console.log('Gun user auth result:', userres, gun.user().pair());
        if (userres.err) {
          console.log('[NO LOGIN]');
          resolve({user: gun.user().pair(), err: userres.err});
        } else {
          console.log('[LOGIN OK!!!]');
          resolve({user: gun.user().pair()});
        }
      });
    });

  const loginUser = async (uname, pass) => {
    const getElapsed = timer();
    await createUser(uname, pass);
    console.log('created', getElapsed());
    const res = await authUser(uname, pass);
    console.log('authenticated', getElapsed());

    setLoginStatus(res);
  };

  const logout = () => {
    gun.user().leave();
    setLoginStatus({user: gun.user().pair()});
  };
  const test = async () => {
    const getElapsed = timer();
    const array = new Uint8Array(10);
    let [random, pair] = await Promise.all([
      crypto.getRandomValues(array),
      SEA.pair(),
    ]);
    console.log({random, pair}, getElapsed());
    setState({random, pair});
    let enc = await SEA.encrypt('hello self', pair);
    console.log({pair, enc}, getElapsed());
    let signed = await SEA.sign(enc, pair);
    console.log({signed}, getElapsed());
    let verified = await SEA.verify(signed, pair.pub);
    console.log({verified}, getElapsed());
    let decrypted = await SEA.decrypt(verified, pair);
    console.log({decrypted}, getElapsed());
    setState(prev => ({...prev, decrypted}));
  };

  const test2 = async () => {
    const getElapsed = timer();
    const alice = await SEA.pair();
    const bob = await SEA.pair();
    console.log({alice, bob}, getElapsed());
    console.log('Doing some work');
    const check = await SEA.work('hello self', alice);
    console.log('Done work', {check}, getElapsed());
    const aes = await SEA.secret(bob.epub, alice);
    console.log({aes}, getElapsed());
    const shared = await SEA.encrypt('shared data', aes);
    const aes2 = await SEA.secret(alice.epub, bob);
    console.log({shared, aes2}, getElapsed());
    const sharedDecrypted = await SEA.decrypt(shared, aes2);
    console.log({sharedDecrypted}, getElapsed());
    setState(prev => ({...prev, sharedDecrypted}));
  };

  const testQuickWrong = () => {
    return SEA.pair(function(alice) {
      SEA.pair(function(bob) {
        SEA.sign('asdf', alice, function(data) {
          SEA.verify(data, bob.pub, function(msg) {
            if (msg !== undefined)
              throw new Error('msg should equal undefined');
            SEA.verify(data + 1, alice.pub, function(msg) {
              if (msg !== undefined)
                throw new Error('msg should equal undefined');

              SEA.encrypt('secret', alice, function(enc) {
                SEA.decrypt(enc, bob, function(dec) {
                  if (dec !== undefined)
                    throw new Error('dec should equal undefined');
                  SEA.decrypt(enc + 1, alice, function(dec) {
                    if (dec !== undefined)
                      throw new Error('dec should equal undefined');
                  });
                });
              });
            });
          });
        });
      });
    });
  };
  const testTypes = () => {
    var pair, s, v;
    return SEA.pair(function(pair) {
      SEA.sign(null, pair, function(s) {
        SEA.verify(s, pair, function(v) {
          if (v !== null) throw new Error('bad value');
          SEA.sign(true, pair, function(s) {
            SEA.verify(s, pair, function(v) {
              if (v !== true) throw new Error('bad value');
              SEA.sign(false, pair, function(s) {
                SEA.verify(s, pair, function(v) {
                  if (v !== false) throw new Error('bad value');
                  SEA.sign(0, pair, function(s) {
                    SEA.verify(s, pair, function(v) {
                      if (v !== 0) throw new Error('bad value');
                      SEA.sign(1, pair, function(s) {
                        SEA.verify(s, pair, function(v) {
                          if (v !== 1) throw new Error('bad value');
                          SEA.sign(1.01, pair, function(s) {
                            SEA.verify(s, pair, function(v) {
                              if (v !== 1.01) throw new Error('bad value');
                              SEA.sign('', pair, function(s) {
                                SEA.verify(s, pair, function(v) {
                                  if (v !== '') throw new Error('bad value');
                                  SEA.sign('a', pair, function(s) {
                                    SEA.verify(s, pair, function(v) {
                                      if (v !== 'a')
                                        throw new Error('bad value');
                                      SEA.sign([], pair, function(s) {
                                        SEA.verify(s, pair, function(v) {
                                          if (v.length != 0) {
                                            console.log({v});
                                            throw new Error(`bad value ${v}`);
                                          }
                                          SEA.sign([1], pair, function(s) {
                                            SEA.verify(s, pair, function(v) {
                                              if (v[0] != 1)
                                                throw new Error(
                                                  `bad value ${v}`,
                                                );
                                              SEA.sign({}, pair, function(s) {
                                                SEA.verify(s, pair, function(
                                                  v,
                                                ) {
                                                  if (typeof v !== 'object')
                                                    throw new Error(
                                                      `bad value ${v}`,
                                                    );
                                                  SEA.sign(
                                                    {a: 1},
                                                    pair,
                                                    function(s) {
                                                      SEA.verify(
                                                        s,
                                                        pair,
                                                        function(v) {
                                                          if (v.a != 1)
                                                            throw new Error(
                                                              `bad value ${v}`,
                                                            );
                                                          SEA.sign(
                                                            JSON.stringify({
                                                              a: 1,
                                                            }),
                                                            pair,
                                                            function(s) {
                                                              SEA.verify(
                                                                s,
                                                                pair,
                                                                function(v) {
                                                                  if (v.a != 1)
                                                                    throw new Error(
                                                                      `bad value ${v}`,
                                                                    );
                                                                },
                                                              );
                                                            },
                                                          );
                                                        },
                                                      );
                                                    },
                                                  );
                                                });
                                              });
                                            });
                                          });
                                        });
                                      });
                                    });
                                  });
                                });
                              });
                            });
                          });
                        });
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  };
  return (
    <View style={styles.container}>
      <WebviewCrypto />
      <View style={{flexDirection: 'row'}}>
        <Text>change peer:</Text>
        <TextInput
          onChangeText={setPeer}
          value={peer}
          style={{borderWidth: 1, width: '50%'}}
        />
      </View>
      <Button onPress={restartGun} title={'reconnect'} />

      <Text>Random: {state.random && state.random.toString()}</Text>
      <Text>SEA Pair: {state.pair && JSON.stringify(state.pair)}</Text>
      <Text>Decrypted: {state.decrypted && state.decrypted}</Text>
      <Text>Shared: {state.sharedDecrypted && state.sharedDecrypted}</Text>

      <Button onPress={runTests} title={'Run SEA tests'} />
      <View style={{flexDirection: 'row'}}>
        <Text>username:</Text>
        <TextInput
          onChangeText={setUserName}
          style={{borderWidth: 1, width: '50%'}}
        />
      </View>
      <View style={{flexDirection: 'row'}}>
        <Text>password:</Text>
        <TextInput
          onChangeText={setPass}
          style={{borderWidth: 1, width: '50%'}}
        />
      </View>
      <Button onPress={loginUser} title={'login user'} />
      <Button onPress={logout} title={'logout user'} />
      <Text>Custom User Status: {JSON.stringify(loginStatus)}</Text>
      <Button onPress={clearStorage} title={'clear storage'} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});
