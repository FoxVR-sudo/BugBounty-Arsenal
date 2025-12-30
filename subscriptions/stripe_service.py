"""
Stripe Payment Service - Full Integration
Handles checkout, subscriptions, webhooks, and billing
"""
import stripe
import logging
from django.conf import settings
from django.utils import timezone
from .models import Plan, Subscription, EnterpriseCustomer, Invoice
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Initialize Stripe
stripe.api_key = settings.STRIPE_SECRET_KEY


class StripeService:
    """Centralized Stripe operations"""
    
    @staticmethod
    def create_customer(user, email=None):
        """Create a Stripe customer for a user"""
        try:
            customer = stripe.Customer.create(
                email=email or user.email,
                name=user.get_full_name() if hasattr(user, 'get_full_name') else user.email,
                metadata={
                    'user_id': str(user.id),
                    'username': user.username if hasattr(user, 'username') else user.email,
                }
            )
            logger.info(f"Created Stripe customer {customer.id} for user {user.email}")
            return customer.id
        except stripe.error.StripeError as e:
            logger.error(f"Stripe customer creation failed: {str(e)}")
            raise
    
    @staticmethod
    def create_payment_intent(user, plan, metadata=None):
        """Create Stripe Payment Intent for embedded payment"""
        try:
            # Get or create customer
            subscription = Subscription.objects.filter(user=user).first()
            
            if subscription and subscription.stripe_customer_id:
                customer_id = subscription.stripe_customer_id
            else:
                customer_id = StripeService.create_customer(user)
                if subscription:
                    subscription.stripe_customer_id = customer_id
                    subscription.save()
            
            # Create payment intent
            intent = stripe.PaymentIntent.create(
                amount=int(plan.price * 100),  # Convert to cents
                currency='usd',
                customer=customer_id,
                metadata=metadata or {},
                automatic_payment_methods={'enabled': True},
                description=f'{plan.display_name} subscription',
            )
            
            logger.info(f"Created Payment Intent {intent.id} for user {user.email} - plan {plan.name}")
            return intent
            
        except stripe.error.StripeError as e:
            logger.error(f"Payment Intent creation failed: {str(e)}")
            raise
    
    @staticmethod
    def create_checkout_session(user, plan, success_url, cancel_url):
        """Create Stripe Checkout Session for subscription"""
        try:
            # Get or create Stripe customer
            subscription = Subscription.objects.filter(user=user).first()
            
            if subscription and subscription.stripe_customer_id:
                customer_id = subscription.stripe_customer_id
            else:
                customer_id = StripeService.create_customer(user)
                if subscription:
                    subscription.stripe_customer_id = customer_id
                    subscription.save()
            
            # Create checkout session
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                mode='subscription',
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': plan.display_name,
                            'description': plan.description or f'{plan.display_name} subscription',
                        },
                        'unit_amount': int(plan.price * 100),  # Convert to cents
                        'recurring': {
                            'interval': 'month',
                        },
                    },
                    'quantity': 1,
                }],
                success_url=success_url + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=cancel_url,
                metadata={
                    'user_id': str(user.id),
                    'plan_id': str(plan.id),
                },
                subscription_data={
                    'metadata': {
                        'user_id': str(user.id),
                        'plan_name': plan.name,
                    }
                },
                allow_promotion_codes=True,
            )
            
            logger.info(f"Created checkout session {session.id} for user {user.email} - plan {plan.name}")
            return session
            
        except stripe.error.StripeError as e:
            logger.error(f"Checkout session creation failed: {str(e)}")
            raise
    
    @staticmethod
    def cancel_subscription(stripe_subscription_id, at_period_end=True):
        """Cancel a Stripe subscription"""
        try:
            if at_period_end:
                subscription = stripe.Subscription.modify(
                    stripe_subscription_id,
                    cancel_at_period_end=True
                )
                logger.info(f"Scheduled cancellation for subscription {stripe_subscription_id}")
            else:
                subscription = stripe.Subscription.cancel(stripe_subscription_id)
                logger.info(f"Immediately cancelled subscription {stripe_subscription_id}")
            
            return subscription
            
        except stripe.error.StripeError as e:
            logger.error(f"Subscription cancellation failed: {str(e)}")
            raise
    
    @staticmethod
    def reactivate_subscription(stripe_subscription_id):
        """Reactivate a cancelled subscription (remove cancel_at_period_end)"""
        try:
            subscription = stripe.Subscription.modify(
                stripe_subscription_id,
                cancel_at_period_end=False
            )
            logger.info(f"Reactivated subscription {stripe_subscription_id}")
            return subscription
            
        except stripe.error.StripeError as e:
            logger.error(f"Subscription reactivation failed: {str(e)}")
            raise
    
    @staticmethod
    def update_subscription(stripe_subscription_id, new_plan):
        """Update subscription to a new plan"""
        try:
            # Get current subscription
            subscription = stripe.Subscription.retrieve(stripe_subscription_id)
            
            # Create a new price for the plan
            price = stripe.Price.create(
                currency='usd',
                unit_amount=int(new_plan.price * 100),
                recurring={'interval': 'month'},
                product_data={
                    'name': new_plan.display_name,
                },
            )
            
            # Update the subscription with the new price
            updated_subscription = stripe.Subscription.modify(
                stripe_subscription_id,
                cancel_at_period_end=False,
                proration_behavior='create_prorations',
                items=[{
                    'id': subscription['items']['data'][0].id,
                    'price': price.id,
                }],
                metadata={
                    'plan_name': new_plan.name,
                }
            )
            
            logger.info(f"Updated subscription {stripe_subscription_id} to plan {new_plan.name}")
            return updated_subscription
            
        except stripe.error.StripeError as e:
            logger.error(f"Subscription update failed: {str(e)}")
            raise
    
    @staticmethod
    def create_billing_portal_session(customer_id, return_url):
        """Create customer portal session for subscription management"""
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url,
            )
            
            logger.info(f"Created billing portal session for customer {customer_id}")
            return session
            
        except stripe.error.StripeError as e:
            logger.error(f"Billing portal session creation failed: {str(e)}")
            raise
    
    @staticmethod
    def handle_checkout_completed(session):
        """Handle successful checkout completion"""
        try:
            user_id = session.metadata.get('user_id')
            plan_id = session.metadata.get('plan_id')
            
            if not user_id or not plan_id:
                logger.error(f"Missing metadata in checkout session {session.id}")
                return
            
            from users.models import User
            user = User.objects.get(id=user_id)
            plan = Plan.objects.get(id=plan_id)
            
            # Get Stripe subscription
            stripe_subscription = stripe.Subscription.retrieve(session.subscription)
            
            # Create or update subscription
            subscription, created = Subscription.objects.update_or_create(
                user=user,
                defaults={
                    'plan': plan,
                    'status': 'active',
                    'stripe_customer_id': session.customer,
                    'stripe_subscription_id': session.subscription,
                    'current_period_start': timezone.make_aware(
                        datetime.fromtimestamp(stripe_subscription.current_period_start)
                    ),
                    'current_period_end': timezone.make_aware(
                        datetime.fromtimestamp(stripe_subscription.current_period_end)
                    ),
                }
            )
            
            action = 'Created' if created else 'Updated'
            logger.info(f"{action} subscription for user {user.email} - plan {plan.name}")
            
        except Exception as e:
            logger.error(f"Error handling checkout completion: {str(e)}")
            raise
    
    @staticmethod
    def handle_subscription_updated(stripe_subscription):
        """Handle subscription update event"""
        try:
            sub_id = stripe_subscription.id
            subscription = Subscription.objects.get(stripe_subscription_id=sub_id)
            
            # Update subscription details
            subscription.status = stripe_subscription.status
            subscription.current_period_start = timezone.make_aware(
                datetime.fromtimestamp(stripe_subscription.current_period_start)
            )
            subscription.current_period_end = timezone.make_aware(
                datetime.fromtimestamp(stripe_subscription.current_period_end)
            )
            subscription.cancel_at_period_end = stripe_subscription.cancel_at_period_end
            subscription.save()
            
            logger.info(f"Updated subscription {sub_id} - status: {stripe_subscription.status}")
            
        except Subscription.DoesNotExist:
            logger.warning(f"Subscription not found for Stripe ID {stripe_subscription.id}")
        except Exception as e:
            logger.error(f"Error handling subscription update: {str(e)}")
            raise
    
    @staticmethod
    def handle_subscription_deleted(stripe_subscription):
        """Handle subscription cancellation"""
        try:
            subscription = Subscription.objects.get(
                stripe_subscription_id=stripe_subscription.id
            )
            subscription.status = 'cancelled'
            subscription.save()
            
            logger.info(f"Cancelled subscription {stripe_subscription.id}")
            
        except Subscription.DoesNotExist:
            logger.warning(f"Subscription not found for Stripe ID {stripe_subscription.id}")
        except Exception as e:
            logger.error(f"Error handling subscription deletion: {str(e)}")
            raise
    
    @staticmethod
    def handle_invoice_paid(invoice):
        """Handle successful invoice payment"""
        try:
            # Update subscription status if needed
            if invoice.subscription:
                subscription = Subscription.objects.filter(
                    stripe_subscription_id=invoice.subscription
                ).first()
                
                if subscription and subscription.status != 'active':
                    subscription.status = 'active'
                    subscription.save()
                    logger.info(f"Activated subscription {invoice.subscription} after payment")
            
            logger.info(f"Invoice {invoice.id} paid successfully")
            
        except Exception as e:
            logger.error(f"Error handling invoice payment: {str(e)}")
    
    @staticmethod
    def handle_payment_intent_succeeded(payment_intent):
        """Handle successful payment intent (for embedded payments)"""
        try:
            # Get metadata
            metadata = payment_intent.metadata
            subscription_id = metadata.get('subscription_id')
            enterprise_customer_id = metadata.get('enterprise_customer_id')
            
            if not subscription_id:
                logger.warning(f"Payment Intent {payment_intent.id} has no subscription_id")
                return
            
            # Get subscription
            subscription = Subscription.objects.get(id=subscription_id)
            
            # Create Stripe subscription
            stripe_subscription = stripe.Subscription.create(
                customer=payment_intent.customer,
                items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': subscription.plan.display_name,
                        },
                        'unit_amount': int(subscription.plan.price * 100),
                        'recurring': {'interval': 'month'},
                    },
                }],
                metadata={
                    'user_id': str(subscription.user.id),
                    'plan_name': subscription.plan.name,
                },
                default_payment_method=payment_intent.payment_method,
            )
            
            # Update subscription
            subscription.status = 'active'
            subscription.stripe_subscription_id = stripe_subscription.id
            subscription.current_period_start = timezone.make_aware(
                datetime.fromtimestamp(stripe_subscription.current_period_start)
            )
            subscription.current_period_end = timezone.make_aware(
                datetime.fromtimestamp(stripe_subscription.current_period_end)
            )
            subscription.save()
            
            # Activate enterprise customer if present
            if enterprise_customer_id:
                try:
                    enterprise = EnterpriseCustomer.objects.get(id=enterprise_customer_id)
                    enterprise.is_active = True
                    enterprise.save()
                    logger.info(f"Activated EnterpriseCustomer {enterprise_customer_id}")
                except EnterpriseCustomer.DoesNotExist:
                    logger.warning(f"EnterpriseCustomer {enterprise_customer_id} not found")
            
            logger.info(f"Payment succeeded for subscription {subscription.id}, created Stripe subscription {stripe_subscription.id}")
            
        except Subscription.DoesNotExist:
            logger.error(f"Subscription {subscription_id} not found for Payment Intent {payment_intent.id}")
        except Exception as e:
            logger.error(f"Error handling payment intent succeeded: {str(e)}")
            raise
            if invoice.subscription:
                subscription = Subscription.objects.filter(
                    stripe_subscription_id=invoice.subscription
                ).first()
                
                if subscription:
                    subscription.status = 'active'
                    subscription.save()
                    logger.info(f"Invoice paid for subscription {invoice.subscription}")
            
        except Exception as e:
            logger.error(f"Error handling invoice payment: {str(e)}")
            raise
    
    @staticmethod
    def handle_invoice_payment_failed(invoice):
        """Handle failed invoice payment"""
        try:
            if invoice.subscription:
                subscription = Subscription.objects.filter(
                    stripe_subscription_id=invoice.subscription
                ).first()
                
                if subscription:
                    subscription.status = 'past_due'
                    subscription.save()
                    logger.warning(f"Payment failed for subscription {invoice.subscription}")
            
        except Exception as e:
            logger.error(f"Error handling invoice payment failure: {str(e)}")
            raise
