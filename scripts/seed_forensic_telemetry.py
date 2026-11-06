"""Forensic Telemetry & Adversary Graph Seeding Script for VFRA-TTI.

Populates the PostgreSQL database with hyper-realistic, Indian jurisdiction-specific
cyber-intelligence data demonstrating full platform capabilities across:
- /radar: Real-time telemetry feed with Indian UPI, crypto rails, defanged URLs, threat scoring.
- /topology: Interconnected relational network graph with dense clusters, forward and reply links.
- /cases: Pre-built court-admissible forensic dossier (CASE-2026-IN-4921) with pinned evidence and analyst notes.

Target Scenarios:
1. Scenario 1: 'Digital Arrest' & Extortion Ring (@cbi_cyber_directorate, @mha_notice_officer, @digital_custody_desk)
2. Scenario 2: High-Velocity Banking Mule Network & 1930 / I4C Evasion (@mule_king_delhi, @fast_disburse_india, @rented_account_broker)
3. Scenario 3: Cross-Border Crypto Laundering / TRC-20 Escrow Bridge (@tron_mixer_desk, @delhi_hawala_crypto, @cross_chain_settler)
"""

import asyncio
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import sys
from pathlib import Path
from uuid import UUID
import uuid

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.security import hash_password
from app.database.models.iam import (
    Role,
    TenantMembership,
    TenantOrganization,
    UserProfile,
)
from app.database.models.intelligence import (
    DerivedContentRepresentation,
    IngestionJob,
    RawEvidenceBlob,
    SourceChannel,
    SourceMessage,
)
from app.database.models.cases import (
    CaseMessageAssociation,
    CaseNote,
    InvestigativeCase,
)
from app.database.models.audit import AuditEventRecord

settings = get_settings()

DEFAULT_TENANT_ID = UUID(settings.TTI_DEFAULT_TENANT_ID)
LEAD_INVESTIGATOR_ID = UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
ADMIN_USER_ID = UUID("f9e8d7c6-b5a4-3210-fedc-ba0987654321")


async def seed_data():
    """Main execution workflow for seeding forensic telemetry."""
    print("=" * 80)
    print("  VFRA-TTI FORENSIC TELEMETRY & ADVERSARY GRAPH SEEDING ENGINE")
    print("=" * 80)
    print(f"Target Database Server: {settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}")
    print(f"Target Default Tenant:  {DEFAULT_TENANT_ID}")

    engine = create_async_engine(
        settings.async_database_url,
        echo=False,
    )
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # ---------------------------------------------------------------------
        # 1. Organization & User Profiles (IAM Baseline)
        # ---------------------------------------------------------------------
        print("\n[+] 1. Initializing Tenant Organization & Investigator Profiles...")

        # 1.1 Tenant Organization
        stmt_org = select(TenantOrganization).where(TenantOrganization.tenant_id == DEFAULT_TENANT_ID)
        org = await session.scalar(stmt_org)
        if not org:
            org = TenantOrganization(
                tenant_id=DEFAULT_TENANT_ID,
                organization_name="Vigilant Forensic Research and Analytics (VFRA-Ops)",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
                created_at_utc=datetime.now(timezone.utc),
            )
            session.add(org)
            print("  -> Created default tenant: VFRA-Ops")
        else:
            print("  -> Tenant organization already exists.")

        # 1.2 User Profiles
        password_hash = hash_password("VigilantForensic@2026!Ops")

        # Lead Investigator
        stmt_lead = select(UserProfile).where(UserProfile.user_id == LEAD_INVESTIGATOR_ID)
        lead_user = await session.scalar(stmt_lead)
        if not lead_user:
            lead_user = UserProfile(
                user_id=LEAD_INVESTIGATOR_ID,
                email_address="dr.vikram.sethi@vigilantforensic.com",
                full_name="Dr. Vikram Sethi (VFRA Lead Cyber Forensic Examiner)",
                password_hash=password_hash,
                account_state="ACTIVE",
                mfa_enforced=True,
            )
            session.add(lead_user)
            print("  -> Created Lead Investigator: Dr. Vikram Sethi")

        # Admin User
        stmt_admin = select(UserProfile).where(UserProfile.user_id == ADMIN_USER_ID)
        admin_user = await session.scalar(stmt_admin)
        if not admin_user:
            admin_user = UserProfile(
                user_id=ADMIN_USER_ID,
                email_address="secops.admin@vigilantforensic.com",
                full_name="Chief SecOps Administrator (VFRA Headquarters)",
                password_hash=password_hash,
                account_state="ACTIVE",
                mfa_enforced=True,
            )
            session.add(admin_user)
            print("  -> Created SecOps Administrator: Chief Admin")

        await session.flush()

        # 1.3 Tenant Memberships
        for u_id, r_id in [
            (LEAD_INVESTIGATOR_ID, "INVESTIGATOR_LEAD"),
            (ADMIN_USER_ID, "TENANT_ADMIN"),
        ]:
            stmt_mem = select(TenantMembership).where(
                TenantMembership.tenant_id == DEFAULT_TENANT_ID,
                TenantMembership.user_id == u_id,
            )
            mem = await session.scalar(stmt_mem)
            if not mem:
                mem = TenantMembership(
                    membership_id=uuid.uuid4(),
                    tenant_id=DEFAULT_TENANT_ID,
                    user_id=u_id,
                    assigned_role=r_id,
                    membership_status="ACTIVE",
                )
                session.add(mem)
                print(f"  -> Bound membership {u_id} to role {r_id}")

        await session.flush()

        # ---------------------------------------------------------------------
        # 2. Source Channels (3 Target Tactical Conduits)
        # ---------------------------------------------------------------------
        print("\n[+] 2. Registering Intelligence Channels...")
        channels_data = [
            {
                "channel_id": "digital_arrest_ops_vault",
                "channel_title": "CBI & Cyber Crime Directorate Notice Vault",
                "channel_handle": "@digital_arrest_ops_vault",
                "source_type": "telegram",
            },
            {
                "channel_id": "mule_accounts_instant_settle",
                "channel_title": "NCR Mule Liquidity & Bank Account Hub",
                "channel_handle": "@mule_accounts_instant_settle",
                "source_type": "telegram",
            },
            {
                "channel_id": "hawala_crypto_bridge",
                "channel_title": "Hawala Crypto OTC & TRC-20 Liquidity Desk",
                "channel_handle": "@hawala_crypto_bridge",
                "source_type": "telegram",
            },
        ]

        for ch in channels_data:
            stmt_ch = select(SourceChannel).where(
                SourceChannel.tenant_id == DEFAULT_TENANT_ID,
                SourceChannel.channel_id == ch["channel_id"],
            )
            existing_ch = await session.scalar(stmt_ch)
            if not existing_ch:
                source_ch = SourceChannel(
                    tenant_id=DEFAULT_TENANT_ID,
                    channel_id=ch["channel_id"],
                    channel_title=ch["channel_title"],
                    channel_handle=ch["channel_handle"],
                    source_type=ch["source_type"],
                    is_authorized=True,
                )
                session.add(source_ch)
                print(f"  -> Registered authorized channel #{ch['channel_id']}")
            else:
                print(f"  -> Channel #{ch['channel_id']} already exists.")

        await session.flush()

        # ---------------------------------------------------------------------
        # 3. Forensic Messages, Threat Signals, and IOCs
        # ---------------------------------------------------------------------
        print("\n[+] 3. Seeding Forensic Messages & Adversary Relational Edges...")
        base_time = datetime.now(timezone.utc) - timedelta(hours=36)

        messages_data = [
            # -----------------------------------------------------------------
            # SCENARIO 1: Digital Arrest & Extortion Ring
            # -----------------------------------------------------------------
            {
                "message_id": "msg_da_101",
                "channel_id": "digital_arrest_ops_vault",
                "source_sequence_id": 101,
                "message_thread_id": "thread_da_01",
                "sender_username": "cbi_cyber_directorate",
                "sender_native_id": "tg_9921001",
                "broadcast_timestamp_utc": base_time + timedelta(minutes=15),
                "reply_to_message_id": None,
                "sanitized_text": (
                    "URGENT STATUTORY NOTICE // CENTRAL BUREAU OF INVESTIGATION (CBI) CYBER CELL NEW DELHI. "
                    "Case Warrant Reference: CBI/ND/2026/8921. You are placed under DIGITAL ARREST for alleged international "
                    "money laundering and darkweb narcotics facilitation. Complete asset forfeiture order will be executed within 60 minutes. "
                    "To obtain provisional clearance and prevent immediate arrest warrant execution, deposit mandatory court collateral to "
                    "Indian Escrow UPI ID: cbi.settlement@okhdfcbank or merchant gateway cyber.penalty@paytm. "
                    "Inspect digitized arrest warrant portal at hxxps://cbi-investigation-portal[.]in/case-verify. "
                    "Do not terminate Telegram communication or physical STF team will deploy to your geo-location. Contact IO Sharma at +91-98201-44910."
                ),
                "sanitization_flags": ["SCHEME_DEFANGED", "PHONE_MASKED"],
            },
            {
                "message_id": "msg_da_102",
                "channel_id": "digital_arrest_ops_vault",
                "source_sequence_id": 102,
                "message_thread_id": "thread_da_01",
                "sender_username": "mha_notice_officer",
                "sender_native_id": "tg_9921002",
                "broadcast_timestamp_utc": base_time + timedelta(minutes=25),
                "reply_to_message_id": "msg_da_101",
                "sanitized_text": (
                    "Re: Warrant CBI/ND/2026/8921. Notice of Section 91 CrPC compliance served. "
                    "All linked banking accounts across HDFC, SBI, and ICICI will be frozen immediately under the 1930 / I4C national helpline "
                    "unless statutory bond of INR 2,50,000 is settled via UPI ID: cyber.penalty@paytm or wire to nodal mule account broker. "
                    "Verify notice tracking code #CRIME-NCR-4921."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_da_103",
                "channel_id": "digital_arrest_ops_vault",
                "source_sequence_id": 103,
                "message_thread_id": "thread_da_01",
                "sender_username": "digital_custody_desk",
                "sender_native_id": "tg_9921003",
                "broadcast_timestamp_utc": base_time + timedelta(minutes=35),
                "reply_to_message_id": "msg_da_102",
                "sanitized_text": (
                    "Target is inquiring on video interrogation link. Initiate skype/telegram surveillance bridge. "
                    "Forward payment receipt to @cbi_cyber_directorate once UPI cbi.settlement@okhdfcbank receives transaction reference. "
                    "Mirroring clearance portal: hxxps://cbi-investigation-portal[.]in/clearance-ack."
                ),
                "sanitization_flags": ["SCHEME_DEFANGED"],
            },
            {
                "message_id": "msg_da_104",
                "channel_id": "digital_arrest_ops_vault",
                "source_sequence_id": 104,
                "message_thread_id": "thread_da_01",
                "sender_username": "cbi_cyber_directorate",
                "sender_native_id": "tg_9921001",
                "broadcast_timestamp_utc": base_time + timedelta(minutes=45),
                "reply_to_message_id": "msg_da_103",
                "sanitized_text": (
                    "Funds received: 2,50,000 INR confirmed in UPI cbi.settlement@okhdfcbank. "
                    "Routing immediately to Delhi liquidity hub @mule_king_delhi for threshold splitting and laundering."
                ),
                "sanitization_flags": [],
            },

            # -----------------------------------------------------------------
            # SCENARIO 2: High-Velocity Banking Mule Network & 1930 / I4C Evasion
            # -----------------------------------------------------------------
            {
                "message_id": "msg_mule_201",
                "channel_id": "mule_accounts_instant_settle",
                "source_sequence_id": 201,
                "message_thread_id": "thread_mule_01",
                "sender_username": "mule_king_delhi",
                "sender_native_id": "tg_8812001",
                "broadcast_timestamp_utc": base_time + timedelta(hours=2),
                "reply_to_message_id": None,
                "sanitized_text": (
                    "FRESH CORPORATE & CURRENT MULE ACCOUNTS INGESTION ACTIVE. "
                    "HDFC Corporate NetBanking (IFSC: HDFC0001234, Daily limit INR 25 Lakhs) and ICICI Current Account (IFSC: ICIC0005678). "
                    "All accounts come equipped with pre-linked debit cards and active Indian UPI handle: instant.payout@ybl. "
                    "Zero freeze guarantee against national cyber helpline 1930 / I4C reporting for 4 hours. Commission cut: 12% flat. "
                    "DM @mule_king_delhi for immediate escrow assignment."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_mule_202",
                "channel_id": "mule_accounts_instant_settle",
                "source_sequence_id": 202,
                "message_thread_id": "thread_mule_01",
                "sender_username": "fast_disburse_india",
                "sender_native_id": "tg_8812002",
                "broadcast_timestamp_utc": base_time + timedelta(hours=2, minutes=15),
                "reply_to_message_id": "msg_mule_201",
                "sanitized_text": (
                    "Vouch for @mule_king_delhi corporate liquidity. Cleared 18.5 Lakhs from extorted victims this morning. "
                    "Executed automated threshold splitting: sliced into 49,000 INR micro-transactions to stay under automated FIU-IND banking AML limits. "
                    "Secondary disburse UPI handle active: escrow99@axl. Physical cash drop points configured across Connaught Place New Delhi and BKC Mumbai. "
                    "Routing surplus directly into TRC-20 crypto bridge operated by @tron_mixer_desk."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_mule_203",
                "channel_id": "mule_accounts_instant_settle",
                "source_sequence_id": 203,
                "message_thread_id": "thread_mule_01",
                "sender_username": "rented_account_broker",
                "sender_native_id": "tg_8812003",
                "broadcast_timestamp_utc": base_time + timedelta(hours=2, minutes=30),
                "reply_to_message_id": "msg_mule_202",
                "sanitized_text": (
                    "Added 4 additional student KYC accounts in Axis Bank (IFSC: UTIB0000042) and Kotak (IFSC: KKBK0000123). "
                    "Configured UPI routing: instant.payout@ybl. Ready for immediate load testing from Telegram extortion syndicate."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_mule_204",
                "channel_id": "mule_accounts_instant_settle",
                "source_sequence_id": 204,
                "message_thread_id": "thread_mule_01",
                "sender_username": "mule_king_delhi",
                "sender_native_id": "tg_8812001",
                "broadcast_timestamp_utc": base_time + timedelta(hours=2, minutes=45),
                "reply_to_message_id": "msg_mule_203",
                "sanitized_text": (
                    "Batch complete: 42 Lakhs aggregated. Commencing conversion to USDT on Tron network. "
                    "Transmitting proof hash to OTC desk @delhi_hawala_crypto."
                ),
                "sanitization_flags": [],
            },

            # -----------------------------------------------------------------
            # SCENARIO 3: Cross-Border Crypto Laundering (TRC-20 Escrow Bridge)
            # -----------------------------------------------------------------
            {
                "message_id": "msg_cry_301",
                "channel_id": "hawala_crypto_bridge",
                "source_sequence_id": 301,
                "message_thread_id": "thread_crypto_01",
                "sender_username": "tron_mixer_desk",
                "sender_native_id": "tg_7713001",
                "broadcast_timestamp_utc": base_time + timedelta(hours=4),
                "reply_to_message_id": None,
                "sanitized_text": (
                    "RUPEE TO TETHER (USDT) OTC WASHING & HAWALA BRIDGE OPERATIONAL. "
                    "Deposit extorted Indian banking funds via designated mules (@mule_king_delhi), receive untraceable clean USDT. "
                    "Primary Escrow TRC-20 Wallet: TN3W4H6rK2ce4vX9YnFQHwKENnHJoxb3m9. "
                    "Secondary Cold Reserve Wallet: TXaHj89P4vLkM4nQW98vX89mPqLk4jN3v1. "
                    "Minimum ticket: 5,000 USDT. Clean coin guarantee; passed AML screen on major decentralized DEXs."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_cry_302",
                "channel_id": "hawala_crypto_bridge",
                "source_sequence_id": 302,
                "message_thread_id": "thread_crypto_01",
                "sender_username": "delhi_hawala_crypto",
                "sender_native_id": "tg_7713002",
                "broadcast_timestamp_utc": base_time + timedelta(hours=4, minutes=20),
                "reply_to_message_id": "msg_cry_301",
                "sanitized_text": (
                    "Batch payout for NCR Extortion Syndicate Pegasus. Received 42 Lakhs via mule syndicate. "
                    "Transferred 50,000 USDT to Tron TRC-20 address: TN3W4H6rK2ce4vX9YnFQHwKENnHJoxb3m9. "
                    "Alternative multi-chain settlement: Bitcoin escrow bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq and "
                    "Ethereum OTC contract 0x71C7656EC7ab88b098defB751B7401B5f6d8976F. Off-ramp available in Dubai OTC cash."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_cry_303",
                "channel_id": "hawala_crypto_bridge",
                "source_sequence_id": 303,
                "message_thread_id": "thread_crypto_01",
                "sender_username": "cross_chain_settler",
                "sender_native_id": "tg_7713003",
                "broadcast_timestamp_utc": base_time + timedelta(hours=4, minutes=40),
                "reply_to_message_id": "msg_cry_302",
                "sanitized_text": (
                    "Confirming receipt of 50K USDT on Tron wallet TN3W4H6rK2ce4vX9YnFQHwKENnHJoxb3m9. "
                    "Mixer cycle dispatched across 3 intermediate unhosted smart contracts. "
                    "Adversary trail severed; blockchain tracing defeated. Telemetry logs purged."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_cry_304",
                "channel_id": "hawala_crypto_bridge",
                "source_sequence_id": 304,
                "message_thread_id": "thread_crypto_01",
                "sender_username": "tron_mixer_desk",
                "sender_native_id": "tg_7713001",
                "broadcast_timestamp_utc": base_time + timedelta(hours=5),
                "reply_to_message_id": "msg_cry_303",
                "sanitized_text": (
                    "Settlement complete for today. Cumulative volume: 2.4 Million USDT laundered. "
                    "Escrow desk re-opening tomorrow 09:00 IST for state cyber police evasion feeds."
                ),
                "sanitization_flags": [],
            },

            # -----------------------------------------------------------------
            # CROSS-CONDUIT RELATIONAL BRIDGES (To create dense Cytoscape graph)
            # -----------------------------------------------------------------
            {
                "message_id": "msg_bridge_401",
                "channel_id": "digital_arrest_ops_vault",
                "source_sequence_id": 105,
                "message_thread_id": "thread_da_01",
                "sender_username": "cbi_cyber_directorate",
                "sender_native_id": "tg_9921001",
                "broadcast_timestamp_utc": base_time + timedelta(hours=5, minutes=10),
                "reply_to_message_id": "msg_mule_201",  # Cross-channel reply link
                "sanitized_text": (
                    "Acknowledging liquidity allocation from @mule_king_delhi. "
                    "All proceeds from case CBI/ND/2026/8921 successfully cleared through Indian UPI instant.payout@ybl. "
                    "Preparing next extortion batch targeting high net-worth doctors in Maharashtra."
                ),
                "sanitization_flags": [],
            },
            {
                "message_id": "msg_bridge_402",
                "channel_id": "mule_accounts_instant_settle",
                "source_sequence_id": 205,
                "message_thread_id": "thread_mule_01",
                "sender_username": "fast_disburse_india",
                "sender_native_id": "tg_8812002",
                "broadcast_timestamp_utc": base_time + timedelta(hours=5, minutes=20),
                "reply_to_message_id": "msg_cry_301",  # Cross-channel reply link
                "sanitized_text": (
                    "Direct bridge verified: Mule account instant.payout@ybl connected to Tron escrow TN3W4H6rK2ce4vX9YnFQHwKENnHJoxb3m9. "
                    "Cross-border hawala transfer completed."
                ),
                "sanitization_flags": [],
            },
        ]

        for m in messages_data:
            # Check if message already exists
            stmt_msg = select(SourceMessage).where(
                SourceMessage.tenant_id == DEFAULT_TENANT_ID,
                SourceMessage.message_id == m["message_id"],
            )
            existing_msg = await session.scalar(stmt_msg)

            content_bytes = m["sanitized_text"].encode("utf-8")
            content_hash = hashlib.sha256(content_bytes).hexdigest()

            if not existing_msg:
                src_msg = SourceMessage(
                    tenant_id=DEFAULT_TENANT_ID,
                    message_id=m["message_id"],
                    channel_id=m["channel_id"],
                    source_sequence_id=m["source_sequence_id"],
                    message_thread_id=m["message_thread_id"],
                    sender_username=m["sender_username"],
                    sender_native_id=m["sender_native_id"],
                    broadcast_timestamp_utc=m["broadcast_timestamp_utc"],
                    reply_to_message_id=m["reply_to_message_id"],
                    has_media=False,
                )
                session.add(src_msg)

                derived = DerivedContentRepresentation(
                    derived_id=uuid.uuid4(),
                    tenant_id=DEFAULT_TENANT_ID,
                    source_message_id=m["message_id"],
                    sanitized_message_text=m["sanitized_text"],
                    content_sha256=content_hash,
                    sanitization_flags=m["sanitization_flags"],
                )
                session.add(derived)

                raw_blob = RawEvidenceBlob(
                    raw_blob_id=uuid.uuid4(),
                    tenant_id=DEFAULT_TENANT_ID,
                    source_message_id=m["message_id"],
                    payload_sha256_hash=content_hash,
                    byte_size=len(content_bytes),
                    payload_storage_locator=f"evidence/vault/{DEFAULT_TENANT_ID}/{m['message_id']}.json",
                )
                session.add(raw_blob)

                print(f"  -> Ingested message #{m['source_sequence_id']} (@{m['sender_username']}) in #{m['channel_id']}")
            else:
                print(f"  -> Message {m['message_id']} already exists.")

        await session.flush()

        # ---------------------------------------------------------------------
        # 4. Ingestion Batch Provenance Job
        # ---------------------------------------------------------------------
        print("\n[+] 4. Recording Ingestion Batch Provenance Job...")
        stmt_job = select(IngestionJob).where(
            IngestionJob.tenant_id == DEFAULT_TENANT_ID,
            IngestionJob.source_reference == "TELEGRAM_INGESTION_BATCH_2026_NCR",
        )
        existing_job = await session.scalar(stmt_job)
        if not existing_job:
            ingest_job = IngestionJob(
                job_id=uuid.uuid4(),
                tenant_id=DEFAULT_TENANT_ID,
                source_reference="TELEGRAM_INGESTION_BATCH_2026_NCR",
                source_type="telegram",
                status="COMPLETED",
                records_processed=len(messages_data),
                payload_sha256=hashlib.sha256(b"TELEGRAM_INGESTION_BATCH_2026_NCR").hexdigest(),
                submitted_by_user_id=LEAD_INVESTIGATOR_ID,
                completed_at_utc=datetime.now(timezone.utc),
            )
            session.add(ingest_job)
            print(f"  -> Recorded IngestionJob for {len(messages_data)} records.")

        await session.flush()

        # ---------------------------------------------------------------------
        # 5. Pre-Built Case: Cyber Syndicate Pegasus-NCR (CASE-2026-IN-4921)
        # ---------------------------------------------------------------------
        print("\n[+] 5. Seeding Pre-Built Evidentiary Case Dossier (CASE-2026-IN-4921)...")
        case_ref = "CASE-2026-IN-4921"
        stmt_case = select(InvestigativeCase).where(
            InvestigativeCase.tenant_id == DEFAULT_TENANT_ID,
            InvestigativeCase.case_reference == case_ref,
        )
        seeded_case = await session.scalar(stmt_case)

        if not seeded_case:
            case_id = uuid.uuid4()
            seeded_case = InvestigativeCase(
                case_id=case_id,
                tenant_id=DEFAULT_TENANT_ID,
                case_title="Cyber Syndicate Pegasus-NCR: Digital Arrest & Hawala Ring",
                case_reference=case_ref,
                internal_agency_ref="FIR-CRIME-BRANCH-NCR-042/2026",
                case_status="FINALIZED_LOCKED",
                lead_investigator_id=LEAD_INVESTIGATOR_ID,
                description=(
                    "Multi-jurisdictional cyber syndication operating high-pressure 'Digital Arrest' extortion schemes, "
                    "using rent-a-mule UPI accounts across NCR/Mumbai to launder extorted funds into offshore Tron (TRC-20) "
                    "and Ethereum cryptocurrency escrow bridges. Compliant with Section 39 BSA and ISO/IEC 27037 standards."
                ),
                created_at_utc=datetime.now(timezone.utc) - timedelta(days=2),
                closed_at_utc=datetime.now(timezone.utc) - timedelta(hours=3),
            )
            session.add(seeded_case)
            print(f"  -> Created Case Dossier: {case_ref} [FINALIZED_LOCKED]")
            await session.flush()

            # 5.1 Pin Key Messages to the Case
            pinned_items = [
                {
                    "message_id": "msg_da_101",
                    "tags": ["EXTORTION_WARRANT", "INDIAN_UPI", "CRITICAL_96"],
                    "annotation": (
                        "Primary coercive digital arrest demand impersonating CBI Cyber Cell. "
                        "Extracted extortion UPI identifier: cbi.settlement@okhdfcbank."
                    ),
                },
                {
                    "message_id": "msg_mule_201",
                    "tags": ["MULE_BANKING", "1930_EVASION", "HDFC_CORPORATE"],
                    "annotation": (
                        "Interception of corporate current mule accounts deployed to bypass national cyber crime 1930 helpline freezing. "
                        "UPI handle: instant.payout@ybl."
                    ),
                },
                {
                    "message_id": "msg_cry_301",
                    "tags": ["TRC20_ESCROW", "USDT_MIXER", "HAWALA_BRIDGE"],
                    "annotation": (
                        "Offshore conversion conduit into Tron TRC-20 USDT escrow wallet TN3W4H6rK2ce4vX9YnFQHwKENnHJoxb3m9."
                    ),
                },
            ]

            for pin in pinned_items:
                assoc = CaseMessageAssociation(
                    association_id=uuid.uuid4(),
                    tenant_id=DEFAULT_TENANT_ID,
                    case_id=seeded_case.case_id,
                    message_id=pin["message_id"],
                    investigator_tags=pin["tags"],
                    analyst_annotation=pin["annotation"],
                    pinned_by_user_id=LEAD_INVESTIGATOR_ID,
                )
                session.add(assoc)
                print(f"  -> Pinned message {pin['message_id']} to case with tags: {pin['tags']}")

            # 5.2 Add Analyst Hypotheses and Forensic Notes
            case_notes_data = [
                {
                    "title": "Investigative Hypothesis & Threat Actor Attribution",
                    "content": (
                        "Modus operandi correlates directly with organized syndicates operating out of the National Capital Region (NCR) "
                        "and Southeast Asian compound hubs. Actors utilize virtual PBX numbers (+91-98201-44910) and spoofed CBI identity cards. "
                        "Interception reveals exact timing synchronicity between coercive calls and instant mule allocation in @mule_accounts_instant_settle."
                    ),
                },
                {
                    "title": "Financial Forensic Analysis: Multi-Hop Layering Strategy",
                    "content": (
                        "Funds deposited into UPI cbi.settlement@okhdfcbank are divided into sub-threshold tranches of 49,000 INR "
                        "within 90 seconds to evade automated AML flagging by Indian commercial banks. Funds are subsequently aggregated via "
                        "corporate banking mules (instant.payout@ybl) and bridged into Tron (TRC-20) wallet TN3W4H6rK2ce4vX9YnFQHwKENnHJoxb3m9."
                    ),
                },
                {
                    "title": "Statutory Admissibility & Evidence Seal (Sec 39 BSA)",
                    "content": (
                        "Digital evidentiary trail compiled and sealed under Section 39 of the Bharatiya Sakshya Adhiniyam (BSA, 2023) "
                        "and ISO/IEC 27037 standards. SHA-256 integrity hash: 8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4. "
                        "All Telegram packets cryptographically anchored in append-only storage."
                    ),
                },
            ]

            for note in case_notes_data:
                cn = CaseNote(
                    note_id=uuid.uuid4(),
                    tenant_id=DEFAULT_TENANT_ID,
                    case_id=seeded_case.case_id,
                    author_user_id=LEAD_INVESTIGATOR_ID,
                    note_title=note["title"],
                    note_content=note["content"],
                )
                session.add(cn)
                print(f"  -> Added Case Note: '{note['title']}'")

        else:
            print(f"  -> Case {case_ref} already exists.")

        # ---------------------------------------------------------------------
        # 6. Append-Only Audit Trail Records
        # ---------------------------------------------------------------------
        print("\n[+] 6. Generating Audit Trail Ledger Records...")
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=DEFAULT_TENANT_ID,
            user_id=LEAD_INVESTIGATOR_ID,
            action_type="SEED_FORENSIC_TELEMETRY_EXECUTED",
            target_identifier_hash=hashlib.sha256(case_ref.encode("utf-8")).hexdigest(),
            client_ip_address="127.0.0.1",
            correlation_id=uuid.uuid4(),
            details={
                "operation": "TELEMETRY_SEED",
                "scenarios": ["DIGITAL_ARREST", "MULE_NETWORK", "CRYPTO_HAWALA"],
                "messages_seeded": len(messages_data),
                "case_reference": case_ref,
            },
            event_timestamp_utc=datetime.now(timezone.utc),
        )
        session.add(audit_event)

        # Commit all transactions
        await session.commit()
        print("\n" + "=" * 80)
        print("  [SUCCESS] ALL FORENSIC TELEMETRY & ADVERSARY DATA SEEDED CLEANLY!")
        print("=" * 80)


if __name__ == "__main__":
    asyncio.run(seed_data())
