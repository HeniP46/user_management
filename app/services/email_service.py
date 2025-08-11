from builtins import ValueError, dict, str
from settings.config import settings
from app.utils.smtp_connection import SMTPClient
from app.utils.template_manager import TemplateManager
from app.models.user_model import User
import logging

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self, template_manager: TemplateManager):
        self.smtp_client = SMTPClient(
            server=settings.smtp_server,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password
        )
        self.template_manager = template_manager

    async def _send_email(self, to_email: str, subject: str, html_content: str, text_content: str = None) -> bool:
        """
        Internal method to send email with error handling
        """
        try:
            self.smtp_client.send_email(subject, html_content, to_email)
            logger.info(f"Email sent successfully to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False

    async def send_user_email(self, user_data: dict, email_type: str):
        subject_map = {
            'email_verification': "Verify Your Account",
            'password_reset': "Password Reset Instructions",
            'account_locked': "Account Locked Notification"
        }
        if email_type not in subject_map:
            raise ValueError("Invalid email type")
        html_content = self.template_manager.render_template(email_type, **user_data)
        self.smtp_client.send_email(subject_map[email_type], html_content, user_data['email'])

    async def send_verification_email(self, user: User):
        verification_url = f"{settings.server_base_url}verify-email/{user.id}/{user.verification_token}"
        await self.send_user_email({
            "name": user.first_name,
            "verification_url": verification_url,
            "email": user.email
        }, 'email_verification')

    # NEW PROFILE MANAGEMENT NOTIFICATION METHODS
    async def send_professional_upgrade_notification(self, user: User) -> bool:
        """
        Send notification email when user is upgraded to professional status
        """
        try:
            subject = "🎉 Congratulations! You've been upgraded to Professional status"
            
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px;">
                            Congratulations, {user.first_name or user.nickname}! 🎉
                        </h2>
                        <p style="font-size: 16px;">Great news! Your account has been upgraded to <strong>Professional status</strong>.</p>
                        <p style="font-size: 16px;">This upgrade gives you access to additional features and benefits on our platform.</p>
                        
                        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745;">
                            <h3 style="color: #28a745; margin-top: 0;">What's New for You:</h3>
                            <ul style="padding-left: 20px;">
                                <li>Enhanced profile visibility</li>
                                <li>Priority customer support</li>
                                <li>Access to professional features</li>
                                <li>Advanced analytics and insights</li>
                            </ul>
                        </div>
                        
                        <p style="font-size: 16px;">Start exploring your new professional features today!</p>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #666;">Best regards,<br>The Team</p>
                        </div>
                    </div>
                </body>
            </html>
            """
            
            # Plain text version
            text_content = f"""
            Congratulations, {user.first_name or user.nickname}!
            
            Great news! Your account has been upgraded to Professional status.
            This upgrade gives you access to additional features and benefits on our platform.
            
            What's New for You:
            - Enhanced profile visibility
            - Priority customer support
            - Access to professional features
            - Advanced analytics and insights
            
            Start exploring your new professional features today!
            
            Best regards,
            The Team
            """
            
            return await self._send_email(user.email, subject, html_content, text_content)
            
        except Exception as e:
            logger.error(f"Failed to send professional upgrade notification to {user.email}: {e}")
            return False

    async def send_professional_downgrade_notification(self, user: User) -> bool:
        """
        Send notification email when user is downgraded from professional status
        """
        try:
            subject = "Your Professional status has been updated"
            
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #2c3e50; border-bottom: 3px solid #f39c12; padding-bottom: 10px;">
                            Hello, {user.first_name or user.nickname}
                        </h2>
                        <p style="font-size: 16px;">We're writing to inform you that your Professional status has been updated.</p>
                        <p style="font-size: 16px;">Your account has been changed back to standard user status.</p>
                        
                        <div style="background-color: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f39c12;">
                            <h3 style="color: #856404; margin-top: 0;">What This Means:</h3>
                            <ul style="padding-left: 20px;">
                                <li>You still have full access to all standard features</li>
                                <li>Professional-only features are no longer available</li>
                                <li>Your profile and data remain intact</li>
                            </ul>
                        </div>
                        
                        <p style="font-size: 16px;">If you have questions about this change, please don't hesitate to contact our support team.</p>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #666;">Best regards,<br>The Team</p>
                        </div>
                    </div>
                </body>
            </html>
            """
            
            # Plain text version
            text_content = f"""
            Hello, {user.first_name or user.nickname}
            
            We're writing to inform you that your Professional status has been updated.
            Your account has been changed back to standard user status.
            
            What This Means:
            - You still have full access to all standard features
            - Professional-only features are no longer available
            - Your profile and data remain intact
            
            If you have questions about this change, please don't hesitate to contact our support team.
            
            Best regards,
            The Team
            """
            
            return await self._send_email(user.email, subject, html_content, text_content)
            
        except Exception as e:
            logger.error(f"Failed to send professional downgrade notification to {user.email}: {e}")
            return False

    async def send_profile_update_confirmation(self, user: User) -> bool:
        """
        Send confirmation email when user updates their profile
        """
        try:
            subject = "Profile Updated Successfully"
            
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px;">
                            Profile Updated, {user.first_name or user.nickname}!
                        </h2>
                        <p style="font-size: 16px;">Your profile information has been successfully updated.</p>
                        
                        <div style="background-color: #d4edda; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745;">
                            <p style="color: #155724; margin: 0;">✅ Your changes have been saved and are now visible on your profile.</p>
                        </div>
                        
                        <p style="font-size: 16px;">If you didn't make these changes, please contact our support team immediately.</p>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #666;">Best regards,<br>The Team</p>
                        </div>
                    </div>
                </body>
            </html>
            """
            
            text_content = f"""
            Profile Updated, {user.first_name or user.nickname}!
            
            Your profile information has been successfully updated.
            
            ✅ Your changes have been saved and are now visible on your profile.
            
            If you didn't make these changes, please contact our support team immediately.
            
            Best regards,
            The Team
            """
            
            return await self._send_email(user.email, subject, html_content, text_content)
            
        except Exception as e:
            logger.error(f"Failed to send profile update confirmation to {user.email}: {e}")
            return False