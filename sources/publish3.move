module publish3::publication_registry {

    use std::vector;
    use std::signer;
    use std::event;
    use std::timestamp;
    use std::hash;
    use std::bcs;
    use std::ed25519;

    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::table::{Self, Table};

    /*********************************
     * Error codes
     *********************************/
    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_INVALID_PRICE: u64 = 2;
    const E_NOT_AUTHORIZED: u64 = 3;
    const E_EXPIRED: u64 = 4;
    const E_INVALID_RECIPIENT: u64 = 5;
    const E_ALREADY_PUBLISHED: u64 = 6;
    const E_NOT_FOUND: u64 = 7;

    /*********************************
     * Platform fee (basis points)
     *********************************/
    const PLATFORM_FEE_BPS: u64 = 1000; // 10%

    /*********************************
     * Publish3 authority
     *********************************/
    struct P3Authority has key {
        pubkey: ed25519::UnvalidatedPublicKey
    }

    /*********************************
     * Core registry
     *********************************/

    /// paper_uid_hash → Paper
    struct Registry has key {
        papers: Table<vector<u8>, Paper>
    }

    struct Paper has store {
        paper_uid_hash: vector<u8>,
        authors: vector<address>,
        price: u64,
        content_hash: vector<u8>,
        published_at: u64
    }

    /*********************************
     * Capability-based publishing
     *********************************/

    struct PublishCapability has key, drop {
        paper_uid_hash: vector<u8>,
        paper_hash: vector<u8>,
        price: u64,
        expires_at: u64
    }

    struct MintPayload has drop {
        paper_uid_hash: vector<u8>,
        paper_hash: vector<u8>,
        price: u64,
        recipient: address,
        expires_at: u64
    }

    /*********************************
     * Events
     *********************************/

    #[event]
    struct PaperPublished has drop, store {
        paper_uid_hash: vector<u8>,
        authors: vector<address>,
        price: u64
    }

    #[event]
    struct PaperPurchased has drop, store {
        paper_uid_hash: vector<u8>,
        buyer: address,
        amount: u64
    }

    #[event]
    struct RoyaltyDistributed has drop, store {
        paper_uid_hash: vector<u8>,
        buyer: address,
        amount: u64,
        platform_fee: u64,
        author_share: u64,
        per_author_amount: u64
    }

    /*********************************
     * Initialization
     *********************************/

    public entry fun initialize(
        admin: &signer,
        server_pubkey: vector<u8>
    ) {
        assert!(!exists<Registry>(@publish3), E_ALREADY_INITIALIZED);

        move_to(
            admin,
            P3Authority {
                pubkey: ed25519::new_unvalidated_public_key_from_bytes(server_pubkey)
            }
        );

        move_to(
            admin,
            Registry {
                papers: table::new<vector<u8>, Paper>()
            }
        );

        coin::register<AptosCoin>(admin);
    }

    /*********************************
     * Mint publish capability
     *********************************/

    public entry fun mint_publish_capability_with_sig(
        user: &signer,
        paper_uid_hash: vector<u8>,
        paper_hash: vector<u8>,
        price: u64,
        recipient: address,
        expires_at: u64,
        server_signature: vector<u8>
    ) acquires P3Authority {

        let authority = borrow_global<P3Authority>(@publish3);

        let payload = MintPayload {
            paper_uid_hash,
            paper_hash,
            price,
            recipient,
            expires_at
        };

        let payload_hash = hash::sha3_256(bcs::to_bytes(&payload));
        let sig = ed25519::new_signature_from_bytes(server_signature);

        assert!(
            ed25519::signature_verify_strict(&sig, &authority.pubkey, payload_hash),
            E_NOT_AUTHORIZED
        );

        assert!(
            recipient == signer::address_of(user),
            E_INVALID_RECIPIENT
        );

        assert!(
            timestamp::now_seconds() <= expires_at,
            E_EXPIRED
        );

        move_to(
            user,
            PublishCapability {
                paper_uid_hash: payload.paper_uid_hash,
                paper_hash: payload.paper_hash,
                price: payload.price,
                expires_at: payload.expires_at
            }
        );
    }

    /*********************************
     * Publish paper
     *********************************/

    public entry fun publish(
        author: &signer,
        authors: vector<address>
    ) acquires Registry, PublishCapability {

        let PublishCapability {
            paper_uid_hash,
            paper_hash,
            price,
            expires_at
        } = move_from<PublishCapability>(signer::address_of(author));

        assert!(price > 0, E_INVALID_PRICE);
        assert!(timestamp::now_seconds() <= expires_at, E_EXPIRED);
        assert!(vector::length(&authors) > 0, E_INVALID_RECIPIENT);

        let registry = borrow_global_mut<Registry>(@publish3);

        assert!(
            !table::contains(&registry.papers, paper_uid_hash),
            E_ALREADY_PUBLISHED
        );

        let paper = Paper {
            paper_uid_hash,
            authors,
            price,
            content_hash: paper_hash,
            published_at: timestamp::now_seconds()
        };

        table::add(&mut registry.papers, paper_uid_hash, paper);

        event::emit(PaperPublished {
            paper_uid_hash,
            authors,
            price
        });
    }

    /*********************************
     * Purchase
     *********************************/

    public entry fun purchase(
        buyer: &signer,
        paper_uid_hash: vector<u8>
    ) acquires Registry {

        let registry = borrow_global<Registry>(@publish3);

        assert!(
            table::contains(&registry.papers, paper_uid_hash),
            E_NOT_FOUND
        );

        let paper = table::borrow(&registry.papers, paper_uid_hash);

        let author_count = vector::length(&paper.authors);
        assert!(author_count > 0, E_INVALID_RECIPIENT);

        let amount = paper.price;
        let payment = coin::withdraw<AptosCoin>(buyer, amount);

        let platform_fee = (amount * PLATFORM_FEE_BPS) / 10000;
        let author_share = amount - platform_fee;

        let per_author_amount = author_share / author_count;
        let remainder = author_share - (per_author_amount * author_count);
        let total_platform_fee = platform_fee + remainder;

        let platform_coin = coin::extract(&mut payment, total_platform_fee);
        coin::deposit(@publish3, platform_coin);

        let i = 0;
        while (i < author_count) {
            let author = *vector::borrow(&paper.authors, i);
            let share = coin::extract(&mut payment, per_author_amount);
            coin::deposit(author, share);
            i = i + 1;
        };

        coin::destroy_zero(payment);

        event::emit(RoyaltyDistributed {
            paper_uid_hash,
            buyer: signer::address_of(buyer),
            amount,
            platform_fee: total_platform_fee,
            author_share: author_share - remainder,
            per_author_amount
        });

        event::emit(PaperPurchased {
            paper_uid_hash,
            buyer: signer::address_of(buyer),
            amount
        });
    }
}
