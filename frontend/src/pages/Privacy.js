import React from 'react';
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiLock } from 'react-icons/fi';

const Privacy = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900">
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-4xl mx-auto px-4 py-6">
          <Link 
            to="/" 
            className="inline-flex items-center gap-2 text-primary hover:text-primary-dark transition mb-4"
          >
            <FiArrowLeft />
            Back to Home
          </Link>
          <div className="flex items-center gap-3">
            <FiLock className="text-primary text-3xl" />
            <h1 className="text-3xl font-bold text-white">Privacy Policy</h1>
          </div>
          <p className="text-gray-400 mt-2">Last Updated: December 31, 2025</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="bg-white rounded-lg shadow-xl p-8 prose prose-lg max-w-none">
          
          <h2>1. Introduction</h2>
          <p>
            BugBounty Arsenal ("we", "us", "our") is committed to protecting your privacy. This Privacy Policy 
            explains how we collect, use, disclose, and safeguard your information when you use our Service.
          </p>

          <h2>2. Information We Collect</h2>
          
          <h3>2.1 Registration Information</h3>
          <ul>
            <li><strong>Email address:</strong> For account creation and communication</li>
            <li><strong>Password:</strong> Stored using bcrypt encryption</li>
            <li><strong>Name:</strong> For personalization</li>
            <li><strong>Phone number:</strong> For SMS verification (optional)</li>
            <li><strong>Address:</strong> For billing purposes (optional)</li>
          </ul>

          <h3>2.2 Usage Information</h3>
          <ul>
            <li><strong>IP address:</strong> For security and fraud prevention</li>
            <li><strong>Browser information:</strong> User agent and device data</li>
            <li><strong>Scan history:</strong> Targets, detectors used, results</li>
            <li><strong>Activity logs:</strong> Login times, actions performed</li>
            <li><strong>Cookies:</strong> For session management and analytics</li>
          </ul>

          <h3>2.3 Payment Information</h3>
          <ul>
            <li><strong>Stripe Customer ID:</strong> We use Stripe for payment processing</li>
            <li><strong>We DO NOT store:</strong> Credit card numbers or CVV codes</li>
            <li>All payment data is handled by Stripe (PCI DSS Level 1 certified)</li>
          </ul>

          <h2>3. How We Use Your Information</h2>
          <ul>
            <li>Provide and maintain the Service</li>
            <li>Process payments and subscriptions</li>
            <li>Send SMS verification codes (via Twilio)</li>
            <li>Improve Service quality and features</li>
            <li>Detect and prevent fraud or abuse</li>
            <li>Send important updates and notifications</li>
            <li>Comply with legal obligations</li>
          </ul>

          <h2>4. Data Sharing and Disclosure</h2>
          <p>We share your information with:</p>
          
          <h3>4.1 Service Providers</h3>
          <ul>
            <li><strong>Stripe:</strong> Payment processing</li>
            <li><strong>Twilio:</strong> SMS verification</li>
            <li><strong>Cloud providers:</strong> Hosting infrastructure</li>
          </ul>

          <h3>4.2 Legal Requirements</h3>
          <p>We may disclose information if required by law, court order, or government request.</p>

          <h3>4.3 What We DO NOT Do</h3>
          <ul>
            <li>We DO NOT sell your personal information</li>
            <li>We DO NOT rent your data to third parties</li>
            <li>We DO NOT share data for marketing purposes</li>
          </ul>

          <h2>5. Data Retention</h2>
          <ul>
            <li><strong>Active accounts:</strong> Data retained while account is active</li>
            <li><strong>Deleted accounts:</strong> Personal data anonymized after 30 days</li>
            <li><strong>Financial records:</strong> Retained for 7 years (legal requirement)</li>
            <li><strong>Security logs:</strong> Retained for 12 months</li>
          </ul>

          <h2>6. Data Security</h2>
          <p>We implement industry-standard security measures:</p>
          <ul>
            <li><strong>Encryption:</strong> SSL/TLS for data in transit</li>
            <li><strong>Password hashing:</strong> bcrypt with salt</li>
            <li><strong>Authentication:</strong> JWT tokens with expiration</li>
            <li><strong>Rate limiting:</strong> Protection against brute force attacks</li>
            <li><strong>Backups:</strong> Encrypted and regularly tested</li>
          </ul>

          <h2>7. Your Rights (GDPR)</h2>
          <p>Under GDPR, you have the right to:</p>
          <ul>
            <li><strong>Access:</strong> Request a copy of your personal data</li>
            <li><strong>Correction:</strong> Update inaccurate or incomplete data</li>
            <li><strong>Deletion:</strong> Request deletion of your data ("right to be forgotten")</li>
            <li><strong>Restriction:</strong> Limit how we process your data</li>
            <li><strong>Portability:</strong> Receive your data in machine-readable format</li>
            <li><strong>Objection:</strong> Object to certain types of processing</li>
            <li><strong>Withdraw consent:</strong> Opt out of optional data processing</li>
          </ul>
          <p>
            To exercise these rights, contact:{' '}
            <a href="mailto:privacy@bugbountyarsenal.com" className="text-primary hover:underline">
              privacy@bugbountyarsenal.com
            </a>
          </p>

          <h2>8. Cookies</h2>
          <p>We use the following types of cookies:</p>
          <ul>
            <li><strong>Essential cookies:</strong> Required for Service functionality</li>
            <li><strong>Functional cookies:</strong> Remember your preferences</li>
            <li><strong>Analytical cookies:</strong> Anonymized usage statistics</li>
          </ul>
          <p>You can manage cookies through your browser settings.</p>

          <h2>9. Children's Privacy</h2>
          <p>
            The Service is not intended for users under 18 years old. We do not knowingly collect data 
            from children. If we discover such data, we will delete it immediately.
          </p>

          <h2>10. International Data Transfers</h2>
          <p>
            Your data may be transferred to and processed in countries outside the EU. We ensure adequate 
            protection through Standard Contractual Clauses (SCCs) approved by the European Commission.
          </p>

          <h2>11. Changes to This Policy</h2>
          <p>
            We may update this Privacy Policy periodically. We will notify you of significant changes via 
            email or Service notification.
          </p>

          <h2>12. Contact Us</h2>
          <p>For privacy-related questions or concerns:</p>
          <ul>
            <li>
              <strong>Email:</strong>{' '}
              <a href="mailto:privacy@bugbountyarsenal.com" className="text-primary hover:underline">
                privacy@bugbountyarsenal.com
              </a>
            </li>
            <li><strong>Data Protection Officer:</strong> Available upon request</li>
          </ul>

          <div className="bg-blue-50 border-l-4 border-blue-400 p-4 my-6">
            <p className="text-sm text-blue-700">
              <strong>GDPR Compliance:</strong> This Privacy Policy complies with the General Data Protection 
              Regulation (EU) 2016/679 and Bulgarian Personal Data Protection Act.
            </p>
          </div>

          <div className="bg-gray-100 border-l-4 border-gray-400 p-4 my-6">
            <p className="text-sm text-gray-700">
              <strong>Version:</strong> 1.0<br />
              <strong>Effective Date:</strong> December 31, 2025<br />
              <strong>Last Revision:</strong> December 31, 2025
            </p>
          </div>

        </div>
      </div>
    </div>
  );
};

export default Privacy;
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiLock } from 'react-icons/fi';

const Privacy = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900">
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-4xl mx-auto px-4 py-6">
          <Link 
            to="/" 
            className="inline-flex items-center gap-2 text-primary hover:text-primary-dark transition mb-4"
          >
            <FiArrowLeft />
            Обратно към начало
          </Link>
          <div className="flex items-center gap-3">
            <FiLock className="text-primary text-3xl" />
            <h1 className="text-3xl font-bold text-white">Политика за поверителност</h1>
          </div>
          <p className="text-gray-400 mt-2">Последна актуализация: 31 Декември 2025</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="bg-white rounded-lg shadow-xl p-8 prose prose-lg max-w-none">
          
          <h2>1. Въведение</h2>
          <p>
            BugBounty Arsenal ("ние", "нас", "нашият") зачита вашата поверителност и се ангажира 
            да защитава вашите лични данни. Тази Политика за поверителност обяснява как събираме, 
            използваме и защитаваме вашата информация.
          </p>

          <div className="bg-blue-50 border-l-4 border-blue-400 p-4 my-4">
            <p className="font-semibold text-blue-800">ℹ️ GDPR Compliance:</p>
            <p className="text-blue-700">
              Тази политика е съобразена с Общия регламент за защита на данните (GDPR) 
              на Европейския съюз и Закона за защита на личните данни на Република България.
            </p>
          </div>

          <h2>2. Събирани данни</h2>
          
          <h3>2.1. Данни при регистрация</h3>
          <ul>
            <li>Имейл адрес (задължително)</li>
            <li>Парола (криптирана)</li>
            <li>Име и фамилия</li>
            <li>Телефонен номер (за SMS верификация)</li>
            <li>Адрес (за Enterprise планове)</li>
          </ul>

          <h3>2.2. Данни при използване</h3>
          <ul>
            <li>IP адрес и device fingerprint</li>
            <li>Browser и операционна система</li>
            <li>История на сканирания (URLs, scan types, results)</li>
            <li>Логове за достъп и действия в системата</li>
            <li>Cookies и local storage данни</li>
          </ul>

          <h3>2.3. Платежна информация</h3>
          <ul>
            <li>Данни за кредитни карти се обработват директно от Stripe (PCI DSS compliant)</li>
            <li>Ние съхраняваме само Stripe Customer ID и последните 4 цифри на картата</li>
            <li>История на фактури и плащания</li>
          </ul>

          <h2>3. Цел на обработката</h2>
          <p>Вашите данни се използват за:</p>
          <ul>
            <li>Предоставяне на услугата и техническа поддръжка</li>
            <li>Обработка на плащания и фактуриране</li>
            <li>SMS верификация за сигурност на акаунта</li>
            <li>Подобряване на качеството на услугата</li>
            <li>Комуникация относно промени, актуализации и оферти</li>
            <li>Спазване на законови изисквания</li>
            <li>Предотвратяване на измами и злоупотреби</li>
          </ul>

          <h2>4. Споделяне на данни</h2>
          <p>Вашите данни могат да бъдат споделени с:</p>
          <ul>
            <li><strong>Stripe:</strong> За обработка на плащания</li>
            <li><strong>Twilio:</strong> За SMS верификация</li>
            <li><strong>Cloud providers:</strong> За хостинг и storage (AWS, DigitalOcean, etc.)</li>
            <li><strong>Органи на реда:</strong> При законово изискване или съдебна заповед</li>
          </ul>
          <p>
            Ние НЕ продаваме, НЕ наемаме и НЕ споделяме вашите данни с трети страни за 
            маркетингови цели без ваше изрично съгласие.
          </p>

          <h2>5. Съхранение на данни</h2>
          <ul>
            <li>Данни за активни акаунти се съхраняват докато акаунтът е активен</li>
            <li>При изтриване на акаунт, данните се анонимизират в рамките на 30 дни</li>
            <li>Финансови записи се съхраняват 7 години (законово изискване)</li>
            <li>Логове за сигурност се съхраняват до 12 месеца</li>
          </ul>

          <h2>6. Сигурност на данните</h2>
          <p>Ние използваме индустриални стандарти за защита:</p>
          <ul>
            <li>SSL/TLS криптиране за всички комуникации</li>
            <li>Bcrypt хеширане на пароли</li>
            <li>JWT токени за authentication</li>
            <li>Rate limiting срещу brute force атаки</li>
            <li>Regular security audits и penetration testing</li>
            <li>Encrypted backups</li>
          </ul>

          <h2>7. Вашите права (GDPR)</h2>
          <p>Вие имате право на:</p>
          <ul>
            <li><strong>Достъп:</strong> Да поискате копие на вашите данни</li>
            <li><strong>Коригиране:</strong> Да коригирате неточни данни</li>
            <li><strong>Изтриване:</strong> Да поискате изтриване на вашите данни ("право да бъдеш забравен")</li>
            <li><strong>Ограничаване:</strong> Да ограничите обработката на вашите данни</li>
            <li><strong>Преносимост:</strong> Да получите данните си в machine-readable формат</li>
            <li><strong>Възражение:</strong> Да възразите срещу обработката на вашите данни</li>
            <li><strong>Оттегляне на съгласие:</strong> Да оттеглите съгласието си по всяко време</li>
          </ul>
          <p>
            За упражняване на тези права, свържете се с нас на: 
            <a href="mailto:privacy@bugbountyarsenal.com" className="text-primary"> privacy@bugbountyarsenal.com</a>
          </p>

          <h2>8. Cookies</h2>
          <p>Използваме следните типове cookies:</p>
          <ul>
            <li><strong>Задължителни:</strong> За authentication и основна функционалност</li>
            <li><strong>Функционални:</strong> За запаметяване на предпочитания</li>
            <li><strong>Аналитични:</strong> За статистика на използването (анонимизирани)</li>
          </ul>
          <p>
            Можете да управлявате cookies чрез настройките на вашия браузър или чрез нашия 
            cookie consent banner.
          </p>

          <h2>9. Деца</h2>
          <p>
            Услугата не е предназначена за лица под 18 години. Не събираме съзнателно данни 
            от непълнолетни. Ако научим, че сме събрали данни от дете, ще ги изтрием незабавно.
          </p>

          <h2>10. Международни трансфери</h2>
          <p>
            Вашите данни могат да бъдат обработвани в страни извън ЕС (напр. AWS US regions). 
            В такива случаи използваме Standard Contractual Clauses (SCCs) за гарантиране на 
            adequat ниво на защита.
          </p>

          <h2>11. Промени в политиката</h2>
          <p>
            При съществени промени в тази политика, ще ви уведомим чрез имейл и ще поискаме 
            ново съгласие, ако е необходимо.
          </p>

          <h2>12. Контакти</h2>
          <p>За въпроси относно тази политика:</p>
          <ul>
            <li>Email: privacy@bugbountyarsenal.com</li>
            <li>DPO (Data Protection Officer): dpo@bugbountyarsenal.com</li>
          </ul>
          <p>
            Можете също да подадете жалба до Комисията за защита на личните данни (КЗЛД) 
            на Република България.
          </p>

          <p className="text-sm text-gray-600 mt-8">
            Версия 1.0 | Последна актуализация: 31 Декември 2025
          </p>
        </div>
      </div>
    </div>
  );
};

export default Privacy;
