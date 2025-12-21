module publish3::publication_registry {

    use std::vector;
    use std::signer;
    use std::event;
    use std::timestamp;
    use std::hash;
    use std::ed25519;
    use std::bcs;
    
    /*********************************
     * Error codes
     *********************************/
    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_INVALID_PRICE: u64 = 2;
    const E_NOT_AUTHORIZED: u64 = 3;
    const E_EXPIRED: u64 = 4;
    const E_INVALID_RECIPIENT: u64 = 5;

    /*********************************
     * Platform fee (basis points)
     *********************************/
    const PLATFORM_FEE_BPS: u64 = 1000; // 10%

    /*********************************
     * Publish 3 authority
     *********************************/

    struct P3Authority has key {
        pubkey: ed25519::UnvalidatedPublicKey
    }

    /*********************************
     * Core registry state
     *********************************/

    /// Global counter for paper IDs
    struct PaperCounter has key {
        next_id: u64
    }

    /// Paper metadata (on-chain reference, not the content)
    struct Paper has store {
        id: u64,
        authors: vector<address>,
        price: u64,
        content_hash: vector<u8>,
        published_at: u64
    }

    /// Global registry (stored once under @publish3)
    struct Registry has key {
        papers: vector<Paper>
    }

    /*********************************
     * Capability-based publishing
     *********************************/

    /// Ephemeral capability that allows a single publish
    struct PublishCapability has key, drop {
        paper_hash: vector<u8>,
        price: u64,
        expires_at: u64
    }

    /// Payload signed by the backend
    struct MintPayload has drop {
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
        paper_id: u64,
        authors: vector<address>,
        price: u64
    }

    #[event]
    struct PaperPurchased has drop, store {
        paper_id: u64,
        buyer: address,
        amount: u64
    }

    #[event]
    struct RoyaltyDistributed has drop, store {
        paper_id: u64,
        buyer: address,
        amount: u64,
        platform_fee: u64,
        author_share: u64,
        per_author_amount: u64
    }

    #[event]
    struct X402PaymentEvent has drop, store {
        recipient: address,
        amount: u64,
        paper_id: u64
    }

    /*********************************
     * Initialization
     *********************************/

    /// Called once at deployment time
    public entry fun initialize(
        admin: &signer,
        server_pubkey: vector<u8>
    ) {
        assert!(
            !exists<Registry>(@publish3),
            E_ALREADY_INITIALIZED
        );

        move_to(
            admin,
            P3Authority { pubkey: ed25519::new_unvalidated_public_key_from_bytes(server_pubkey) }
        );

        move_to(
            admin,
            Registry { papers: vector::empty() }
        );

        move_to(
            admin,
            PaperCounter { next_id: 0 }
        );
    }

    /*********************************
     * Authorization: mint capability
     *********************************/

    public entry fun mint_publish_capability_with_sig(
        user: &signer,
        paper_hash: vector<u8>,
        price: u64,
        recipient: address,
        expires_at: u64,
        server_signature: vector<u8>
    ) acquires P3Authority {

        let authority = borrow_global<P3Authority>(@publish3);

        let payload = MintPayload {
            paper_hash: paper_hash,
            price: price,
            recipient: recipient,
            expires_at: expires_at
        };

        // Verify backend signature
        let payload_hash = hash_payload(&payload);

        let sig = ed25519::new_signature_from_bytes(server_signature);

        assert!(
            ed25519::signature_verify_strict(
                &sig,
                &authority.pubkey,
                payload_hash
            ),
            E_NOT_AUTHORIZED
        );

        // Ensure the capability is minted for the caller
        assert!(
            payload.recipient == signer::address_of(user),
            E_INVALID_RECIPIENT
        );

        // Ensure authorization is still valid
        assert!(
            timestamp::now_seconds() <= payload.expires_at,
            E_EXPIRED
        );

        move_to(
            user,
            PublishCapability {
                paper_hash: payload.paper_hash,
                price: payload.price,
                expires_at: payload.expires_at
            }
        );
    }

    /*********************************
     * Publish paper (consumes capability)
     *********************************/

    public entry fun publish(
        _author: &signer,
        authors: vector<address>
    ) acquires Registry, PaperCounter, PublishCapability {

        let PublishCapability { paper_hash, price, expires_at } = move_from<PublishCapability>(signer::address_of(_author));

        assert!(price > 0, E_INVALID_PRICE);

        // Capability expiration check
        assert!(
            timestamp::now_seconds() <= expires_at,
            E_EXPIRED
        );

        let registry = borrow_global_mut<Registry>(@publish3);
        let counter = borrow_global_mut<PaperCounter>(@publish3);

        let paper = Paper {
            id: counter.next_id,
            authors,
            price,
            content_hash: paper_hash,
            published_at: timestamp::now_seconds()
        };

        vector::push_back(&mut registry.papers, paper);

        event::emit(PaperPublished {
            paper_id: counter.next_id,
            authors,
            price: price
        });

        counter.next_id += 1;
    }

    /*********************************
     * Purchase (x402-compatible)
     *********************************/

    public entry fun purchase(
        buyer: &signer,
        paper_id: u64,
        amount: u64
    ) acquires Registry {

        let registry = borrow_global<Registry>(@publish3);
        let paper_ref = vector::borrow(&registry.papers, paper_id);

        assert!(amount >= paper_ref.price, E_INVALID_PRICE);

        // Calculate royalty distribution
        // Platform fee: 10% of purchase amount
        let platform_fee = (amount * PLATFORM_FEE_BPS) / 10000;
        
        // Author share: 90% of purchase amount  
        let author_share = amount - platform_fee;
        
        // Calculate per-author amount (equal split)
        let author_count = vector::length(&paper_ref.authors);
        let per_author_amount = if (author_count > 0) {
            author_share / author_count
        } else {
            0
        };
        
        // Handle remainder from division (give to platform)
        let remainder = if (author_count > 0) {
            author_share - (per_author_amount * author_count)
        } else {
            author_share
        };
        
        let total_platform_fee = platform_fee + remainder;

        // Emit royalty distribution event
        event::emit(RoyaltyDistributed {
            paper_id,
            buyer: signer::address_of(buyer),
            amount,
            platform_fee: total_platform_fee,
            author_share: author_share - remainder, // actual distributed to authors
            per_author_amount
        });

        // Emit x402 payment events (placeholders for actual x402 integration)
        // Platform payment
        event::emit(X402PaymentEvent {
            recipient: @publish3, // Platform address
            amount: total_platform_fee,
            paper_id
        });

        // Author payments
        let i = 0;
        while (i < author_count) {
            let author_address = *vector::borrow(&paper_ref.authors, i);
            event::emit(X402PaymentEvent {
                recipient: author_address,
                amount: per_author_amount,
                paper_id
            });
            i = i + 1;
        };

        // Also emit the original purchase event for compatibility
        event::emit(PaperPurchased {
            paper_id,
            buyer: signer::address_of(buyer),
            amount
        });
    }

    /*********************************
     * Helpers
     *********************************/

    fun hash_payload(payload: &MintPayload): vector<u8> {
        hash::sha3_256(
            bcs::to_bytes(payload)
        )
    }
}
