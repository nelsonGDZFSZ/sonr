"use strict";(self.webpackChunksonr_docs=self.webpackChunksonr_docs||[]).push([[288],{3905:function(e,t,n){n.d(t,{Zo:function(){return c},kt:function(){return h}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var d=r.createContext({}),l=function(e){var t=r.useContext(d),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},c=function(e){var t=l(e.components);return r.createElement(d.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},u=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,d=e.parentName,c=s(e,["components","mdxType","originalType","parentName"]),u=l(n),h=a,m=u["".concat(d,".").concat(h)]||u[h]||p[h]||o;return n?r.createElement(m,i(i({ref:t},c),{},{components:n})):r.createElement(m,i({ref:t},c))}));function h(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,i=new Array(o);i[0]=u;var s={};for(var d in t)hasOwnProperty.call(t,d)&&(s[d]=t[d]);s.originalType=e,s.mdxType="string"==typeof e?e:a,i[1]=s;for(var l=2;l<o;l++)i[l]=n[l];return r.createElement.apply(null,i)}return r.createElement.apply(null,n)}u.displayName="MDXCreateElement"},936:function(e,t,n){n.r(t),n.d(t,{assets:function(){return c},contentTitle:function(){return d},default:function(){return h},frontMatter:function(){return s},metadata:function(){return l},toc:function(){return p}});var r=n(7462),a=n(3366),o=(n(7294),n(3905)),i=["components"],s={title:"ADR-001",id:"adr-001",displayed_sidebar:"resourcesSidebar"},d=void 0,l={unversionedId:"reference/adr-001",id:"reference/adr-001",title:"ADR-001",description:"Abstract",source:"@site/articles/reference/ADR-001.md",sourceDirName:"reference",slug:"/reference/adr-001",permalink:"/articles/reference/adr-001",editUrl:"https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/articles/reference/ADR-001.md",tags:[],version:"current",frontMatter:{title:"ADR-001",id:"adr-001",displayed_sidebar:"resourcesSidebar"},sidebar:"resourcesSidebar",next:{title:"ADR-002",permalink:"/articles/reference/adr-002"}},c={},p=[{value:"Abstract",id:"abstract",level:2},{value:"DID Method Name",id:"did-method-name",level:2},{value:"DID Method Specific Identifier",id:"did-method-specific-identifier",level:2},{value:"Relationship between DIDs and Sonr wallet accounts",id:"relationship-between-dids-and-sonr-wallet-accounts",level:3},{value:"DID Document Format (JSON-LD)",id:"did-document-format-json-ld",level:2},{value:"<code>controller</code>",id:"controller",level:3},{value:"<code>id</code>",id:"id",level:3},{value:"<code>alsoKnownAs</code>",id:"alsoknownas",level:3},{value:"<code>assertionMethod</code>",id:"assertionmethod",level:3},{value:"<code>verificationMethod</code>",id:"verificationmethod",level:3},{value:"Create -  *<strong>*<code>RegisterName()</code>**</strong>",id:"create----registername",level:2},{value:"Next Logical Steps",id:"next-logical-steps",level:3}],u={toc:p};function h(e){var t=e.components,n=(0,a.Z)(e,i);return(0,o.kt)("wrapper",(0,r.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"abstract"},"Abstract"),(0,o.kt)("p",null,"Sonr is a privacy focused blockchain built to reinvent how we handle identity and data transmission. Sonr also supports DID operations. DIDs are created and stored in the Sonr Node, and they are used with verifiable credentials."),(0,o.kt)("p",null,"This specification describes how DIDs are managed on the Sonr."),(0,o.kt)("h2",{id:"did-method-name"},"DID Method Name"),(0,o.kt)("p",null,"The name-string is ",(0,o.kt)("inlineCode",{parentName:"p"},"snr"),"."),(0,o.kt)("p",null,"A DID must begin with the prefix: ",(0,o.kt)("inlineCode",{parentName:"p"},"did:snr")," in lowercase."),(0,o.kt)("h2",{id:"did-method-specific-identifier"},"DID Method Specific Identifier"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},'sonr-did = "did:snr:" idstring\nidstring = 32*44(base58)\nbase58 = "1" / "2" / "3" / "4" / "5" / "6" / "7" / "8" / "9" / "A" / "B" /\n         "C" / "D" / "E" / "F" / "G" / "H" / "J" / "K" / "L" / "M" / "N" /\n         "P" / "Q" / "R" / "S" / "T" / "U" / "V" / "W" / "X" / "Y" / "Z" /\n         "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h" / "i" / "j" / "k" /\n         "m" / "n" / "o" / "p" / "q" / "r" / "s" / "t" / "u" / "v" / "w" /\n         "x" / "y" / "z"\n\n')),(0,o.kt)("p",null,"The ",(0,o.kt)("inlineCode",{parentName:"p"},"idstring")," is a base58-encoded SHA-256 hash of a Secp256k1 public key, otherwise known as the Sonr Blockchain Wallet address. This means that DIDs are case-sensitive, even though the prefix is always lower-case. The Sonr Highway CLI provides a tool for generating the Secp256k1 key-pair either randomly or from a BIP44 mnemonic provided by the user."),(0,o.kt)("p",null,(0,o.kt)("strong",{parentName:"p"},"Example"),":"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"did:snr:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm\n\n")),(0,o.kt)("h3",{id:"relationship-between-dids-and-sonr-wallet-accounts"},"Relationship between DIDs and Sonr wallet accounts"),(0,o.kt)("p",null,"Sonr Blockchain Wallets are integrated within every Motor powered application. The Sonr Motor is a light peer-to-peer node embedded within every decentralized application built with the Highway SDK. From here on, a Sonr Blockchain Wallet Account will be referenced as a motor."),(0,o.kt)("h2",{id:"did-document-format-json-ld"},"DID Document Format (JSON-LD)"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre",className:"language-json"},'{\n  "@context": "https://www.w3.org/ns/did/v1",\n\n    // All connected Motor Nodes for a Sonr User\n  "controller":[\n        "did:snr:123",\n    ],\n\n    // Address to Multisig wallet for all user motor nodes\n  "id": "did:snr:abc",\n\n    // Registered alias (.snr) names\n  "alsoKnownAs": [\n    "test.snr",\n    "example.snr"\n  ],\n\n    // User authenticated application credentials get stored as assertionMethod\n    "assertionMethod": [...],\n\n    // Connected Motors webauthn credentials get stored as verificationMethod\n  "verificationMethod": [\n    {\n            // Set to Motor Nodes Wallet Address\n      "controller": "did:snr:123",\n\n            // Id of Key set to unique value and operating system/architecture\n      "id": "did:snr:123#ios-arm64-1",\n\n            // JWK generated from WebAuthN Credential\n      "publicKeyJwk": {\n        "crv": "P-256",\n        "kty": "EC",\n        "x": "UANQ8pgvJT33JbrnwMiu1L1JCGQFOEm1ThaNAJcFrWA=",\n        "y": "UWm6q5n1iXyeCJLMGDInN40bkkKr8KkoTWDqJBZQXRo="\n      },\n      "type": "JsonWebKey2020"\n    }\n  ],\n\n    // User public facing services\n    "service": [{\n        // Inbound/Outbound Mailbox - Sonr Core Service\n    "id":"snr:123#mailbox",\n    "type": "EncryptedDataVault",\n        // MultiAddr of hosted IPFS node\n    "serviceEndpoint": "/ip4/159.313.1.45/tcp/57665/peer/123/snr/test"\n  }]\n}\n')),(0,o.kt)("h3",{id:"controller"},(0,o.kt)("inlineCode",{parentName:"h3"},"controller")),(0,o.kt)("p",null,"Currently, the controller represents the set of DIDs associated with the top-level document for a User. In order for the controller to be valid an accompanying entry must be present in the ",(0,o.kt)("inlineCode",{parentName:"p"},"verificationMethod")," and must conform to the *",(0,o.kt)("strong",{parentName:"p"},"*",(0,o.kt)("a",{parentName:"strong",href:"https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/"},"FIDO2 WebAuthn"),"**")," specification."),(0,o.kt)("h3",{id:"id"},(0,o.kt)("inlineCode",{parentName:"h3"},"id")),(0,o.kt)("p",null,"The ID of the DIDDocument is created from the ",(0,o.kt)("inlineCode",{parentName:"p"},"multisignature")," key address returned from the set of all ",(0,o.kt)("inlineCode",{parentName:"p"},"PublicKey")," \u2019s present with matching controllers. The ",(0,o.kt)("inlineCode",{parentName:"p"},"id")," is regenerated on every instance a controller is added or removed from the DIDDocument."),(0,o.kt)("h3",{id:"alsoknownas"},(0,o.kt)("inlineCode",{parentName:"h3"},"alsoKnownAs")),(0,o.kt)("p",null,"This property is utilized to provide resolvable aliases to the associated DIDDocument. Users purchase a name alias which is suffixed by, .snr, a resolvable TLD on the ",(0,o.kt)("a",{parentName:"p",href:"https://handshake.org/"},"Handshake Network"),". Motor nodes are packaged with the lightweight ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/handshake-org/hnsd"},"HNS Resolver"),"."),(0,o.kt)("h3",{id:"assertionmethod"},(0,o.kt)("inlineCode",{parentName:"h3"},"assertionMethod")),(0,o.kt)("p",null,"This property is currently being used to store authenticated application credentials. When Users first access an application, they utilize the account DID in order to authenticate their session."),(0,o.kt)("h3",{id:"verificationmethod"},(0,o.kt)("inlineCode",{parentName:"h3"},"verificationMethod")),(0,o.kt)("p",null,"This property is utilized for storing the individual Motor ",(0,o.kt)("inlineCode",{parentName:"p"},"WebAuthn")," credentials. This mechanism is put into place to associate users by individual devices opposed to strictly an account based structure."),(0,o.kt)("h1",{id:"crud-operations"},"CRUD Operations"),(0,o.kt)("h2",{id:"create----registername"},"Create -  *",(0,o.kt)("strong",{parentName:"h2"},"*",(0,o.kt)("inlineCode",{parentName:"strong"},"RegisterName()"),"**")),(0,o.kt)("p",null,"To create a DID Document in Sonr, the following transaction should be submitted."),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"GET: v1/name/register/start/:username      // Initialize Webauthn Process\nPOST:v1/name/register/finish/:username     // Complete. Send Tx to Blockchain\n\n- (`string`) NameToRegister     : The name to register\n- (`string`) Creator            : The Account Address signing this message\n- (`Credential`) Credential     : Webauthn credential to use for registration\n- (`map`) Metadata              : Metadata to attach to the `WhoIs` record\n")),(0,o.kt)("p",null,"The request must have a valid WebAuthn Credential and an available alias name to register a DIDDocument. The request must also provide an ",(0,o.kt)("strong",{parentName:"p"},"available alias name")," and a valid wallet address (",(0,o.kt)("em",{parentName:"p"},"Creator"),") for the accompanying motor node."),(0,o.kt)("h3",{id:"next-logical-steps"},"Next Logical Steps"),(0,o.kt)("p",null,"The Sonr Blockchain node extracts the ",(0,o.kt)("inlineCode",{parentName:"p"},"COSEKey")," from the ",(0,o.kt)("inlineCode",{parentName:"p"},"Credential")," in order to decode the ",(0,o.kt)("inlineCode",{parentName:"p"},"PublicKey"),"."),(0,o.kt)("h1",{id:"-wip"},"\ud83d\udedf WIP"))}h.isMDXComponent=!0}}]);