"""
Stripe webhook handlers for processing payment events.
"""

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.conf import settings
import stripe
import logging

from .stripe_utils import (
    handle_checkout_session_completed,
    handle_subscription_updated,
    handle_subscription_deleted,
    handle_invoice_payment_succeeded,
)

logger = logging.getLogger(__name__)
stripe.api_key = settings.STRIPE_SECRET_KEY


@csrf_exempt
@require_POST
def stripe_webhook(request):
    """
    Handle Stripe webhook events.
    
    Processes payment-related events from Stripe including:
    - checkout.session.completed
    - customer.subscription.updated
    - customer.subscription.deleted
    - invoice.payment_succeeded
    """
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    
    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        # Invalid payload
        logger.error("Stripe webhook: Invalid payload")
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        logger.error("Stripe webhook: Invalid signature")
        return HttpResponse(status=400)
    
    # Handle the event
    event_type = event['type']
    event_data = event['data']['object']
    
    try:
        if event_type == 'checkout.session.completed':
            # Payment successful, activate subscription
            logger.info(f"Processing checkout.session.completed: {event_data['id']}")
            handle_checkout_session_completed(event_data)
        
        elif event_type == 'customer.subscription.updated':
            # Subscription updated (status change, renewal, etc.)
            logger.info(f"Processing subscription.updated: {event_data['id']}")
            handle_subscription_updated(event_data)
        
        elif event_type == 'customer.subscription.deleted':
            # Subscription canceled
            logger.info(f"Processing subscription.deleted: {event_data['id']}")
            handle_subscription_deleted(event_data)
        
        elif event_type == 'invoice.payment_succeeded':
            # Recurring payment succeeded
            logger.info(f"Processing invoice.payment_succeeded: {event_data['id']}")
            handle_invoice_payment_succeeded(event_data)
        
        elif event_type == 'invoice.payment_failed':
            # Recurring payment failed
            logger.warning(f"Payment failed for invoice: {event_data['id']}")
            # Could add logic to notify user or suspend subscription
        
        else:
            logger.info(f"Unhandled webhook event type: {event_type}")
    
    except Exception as e:
        logger.error(f"Error processing webhook {event_type}: {str(e)}")
        return HttpResponse(status=500)
    
    return HttpResponse(status=200)
