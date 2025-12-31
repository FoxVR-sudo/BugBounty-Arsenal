import React from 'react';
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiShield } from 'react-icons/fi';

const Terms = () => {
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
            <FiShield className="text-primary text-3xl" />
            <h1 className="text-3xl font-bold text-white">Terms of Service</h1>
          </div>
          <p className="text-gray-400 mt-2">Last Updated: December 31, 2025</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="bg-white rounded-lg shadow-xl p-8 prose prose-lg max-w-none">
          
          <h2>1. Acceptance of Terms</h2>
          <p>
            By using BugBounty Arsenal ("the Service"), you agree to comply with these Terms of Service. 
            If you do not agree with these terms, please do not use the Service.
          </p>

          <h2>2. Service Description</h2>
          <p>
            BugBounty Arsenal is an automated vulnerability scanning tool for web applications, designed 
            for ethical hackers, penetration testers, and security researchers.
          </p>

          <h2>3. Legal Use</h2>
          <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 my-4">
            <p className="font-semibold text-yellow-800">⚠️ IMPORTANT:</p>
            <p className="text-yellow-700">
              You agree to use the Service ONLY for:
            </p>
            <ul className="text-yellow-700">
              <li>Testing systems you own</li>
              <li>Testing systems for which you have explicit written authorization</li>
              <li>Participating in authorized bug bounty programs</li>
              <li>Educational purposes in controlled environments</li>
            </ul>
          </div>

          <h2>4. Prohibited Activities</h2>
          <div className="bg-red-50 border-l-4 border-red-500 p-4 my-4">
            <p className="font-semibold text-red-800">🚫 STRICTLY FORBIDDEN:</p>
            <ul className="text-red-700">
              <li>Scanning systems without explicit authorization</li>
              <li>Using the Service for illegal purposes</li>
              <li>Denial of service attacks or system damage</li>
              <li>Unauthorized data exfiltration</li>
              <li>Public disclosure of vulnerabilities without owner consent</li>
            </ul>
          </div>

          <h2>5. User Responsibility</h2>
          <p>
            You are solely responsible for your use of the Service. You acknowledge that:
          </p>
          <ul>
            <li>You must obtain proper authorization before scanning any system</li>
            <li>You must comply with all applicable laws and regulations</li>
            <li>You are responsible for any damages resulting from your actions</li>
            <li>You will practice responsible disclosure of any vulnerabilities found</li>
          </ul>

          <h2>6. Limitation of Liability</h2>
          <p className="font-semibold">
            BugBounty Arsenal and its operators are NOT LIABLE for:
          </p>
          <ul>
            <li>Any illegal use of the Service by users</li>
            <li>Damages to systems scanned by users</li>
            <li>Legal consequences of unauthorized scanning</li>
            <li>Financial losses or reputational damage</li>
            <li>False positives or missed vulnerabilities</li>
          </ul>

          <h2>7. Subscription Plans and Pricing</h2>
          <p>The Service offers the following subscription tiers:</p>
          <ul>
            <li><strong>Free Plan:</strong> €0/month - Limited features</li>
            <li><strong>Pro Plan:</strong> €9.99/month - Full features</li>
            <li><strong>Enterprise Plan:</strong> €49.99/month - Advanced features and support</li>
          </ul>
          <p>Prices may change with 30 days notice. Subscriptions renew automatically.</p>

          <h2>8. Account Termination</h2>
          <p>
            We reserve the right to terminate accounts that:
          </p>
          <ul>
            <li>Violate these Terms of Service</li>
            <li>Engage in illegal scanning activities</li>
            <li>Abuse the Service or infrastructure</li>
            <li>Fail to pay subscription fees</li>
          </ul>

          <h2>9. Intellectual Property</h2>
          <p>
            All content, features, and functionality of BugBounty Arsenal are owned by us and protected 
            by international copyright, trademark, and other intellectual property laws.
          </p>

          <h2>10. Changes to Terms</h2>
          <p>
            We may modify these Terms at any time. Continued use of the Service after changes constitutes 
            acceptance of the new Terms.
          </p>

          <h2>11. Governing Law</h2>
          <p>
            These Terms are governed by the laws of Bulgaria. Any disputes shall be resolved in the courts 
            of Sofia, Bulgaria.
          </p>

          <h2>12. Contact Information</h2>
          <p>
            For questions about these Terms, contact us at:{' '}
            <a href="mailto:legal@bugbountyarsenal.com" className="text-primary hover:underline">
              legal@bugbountyarsenal.com
            </a>
          </p>

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

export default Terms;
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiShield } from 'react-icons/fi';

const Terms = () => {
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
            <FiShield className="text-primary text-3xl" />
            <h1 className="text-3xl font-bold text-white">Общи условия заползване</h1>
          </div>
          <p className="text-gray-400 mt-2">Последна актуализация: 31 Декември 2025</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="bg-white rounded-lg shadow-xl p-8 prose prose-lg max-w-none">
          
          <h2>1. Приемане на условията</h2>
          <p>
            Чрез използването на BugBounty Arsenal ("Услугата"), вие се съгласявате да спазвате 
            настоящите Общи условия. Ако не сте съгласни с тези условия, моля не използвайте Услугата.
          </p>

          <h2>2. Описание на услугата</h2>
          <p>
            BugBounty Arsenal е автоматизиран инструмент за сканиране на уязвимости в уеб приложения, 
            предназначен за ethical hackers, penetration testers и security researchers.
          </p>

          <h2>3. Легално използване</h2>
          <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 my-4">
            <p className="font-semibold text-yellow-800">⚠️ ВАЖНО:</p>
            <p className="text-yellow-700">
              Вие се задължавате да използвате Услугата САМО за:
            </p>
            <ul className="text-yellow-700">
              <li>Тестване на системи, които притежавате</li>
              <li>Тестване на системи, за които имате изрично писмено разрешение</li>
              <li>Участие в легални bug bounty програми</li>
              <li>Образователни цели в контролирана среда</li>
            </ul>
          </div>

          <h2>4. Забранени дейности</h2>
          <p>Строго забранено е:</p>
          <ul>
            <li>Сканиране на системи без разрешение на собственика</li>
            <li>Използване на Услугата за нарушаване на законите</li>
            <li>Причиняване на щети на тествани системи (DoS, data corruption, etc.)</li>
            <li>Споделяне на открити уязвимости без разрешение (публично disclosure)</li>
            <li>Използване на Услугата за измама, krack или други злонамерени цели</li>
          </ul>

          <h2>5. Отговорност на потребителя</h2>
          <p>
            Вие носите пълна отговорност за всички действия, извършени чрез вашия акаунт. 
            Вие сте отговорни за:
          </p>
          <ul>
            <li>Спазване на всички приложими закони и регулации</li>
            <li>Получаване на необходимите разрешения преди сканиране</li>
            <li>Безопасно съхранение на данни от сканирания</li>
            <li>Незабавно докладване на критични уязвимости на засегнатите страни</li>
          </ul>

          <h2>6. Ограничение на отговорността</h2>
          <p>
            BugBounty Arsenal и неговите разработчици НЕ носят отговорност за:
          </p>
          <ul>
            <li>Незаконно използване на Услугата от потребители</li>
            <li>Щети, причинени на тествани системи</li>
            <li>Загуба на данни или бизнес щети</li>
            <li>Точността или пълнотата на резултатите от сканиране</li>
            <li>False positives или false negatives в резултатите</li>
          </ul>

          <h2>7. Абонаментни планове</h2>
          <p>
            Услугата предлага няколко нива на достъп:
          </p>
          <ul>
            <li><strong>Free Plan:</strong> Базови функционалности с ограничения</li>
            <li><strong>Pro Plan:</strong> Разширени функции за €9.99/месец</li>
            <li><strong>Enterprise Plan:</strong> Пълен достъп за €49.99/месец</li>
          </ul>
          <p>
            Плащанията се обработват чрез Stripe. При отказ от абонамент, достъпът до платени 
            функции се запазва до края на текущия платен период.
          </p>

          <h2>8. Прекратяване на достъп</h2>
          <p>
            Запазваме си правото да прекратим или suspend-нем вашия акаунт незабавно при:
          </p>
          <ul>
            <li>Нарушение на настоящите Условия</li>
            <li>Злоупотреба с Услугата</li>
            <li>Незаконни дейности</li>
            <li>Непълнолетие (под 18 години)</li>
          </ul>

          <h2>9. Интелектуална собственост</h2>
          <p>
            Всички права върху BugBounty Arsenal, включително код, дизайн, логота и документация, 
            принадлежат на разработчиците. Използването на Услугата не ви дава права върху 
            интелектуалната собственост.
          </p>

          <h2>10. Промени в условията</h2>
          <p>
            Запазваме си правото да променяме тези Условия по всяко време. При съществени промени, 
            ще бъдете уведомени чрез имейл или съобщение в платформата. Продължаването на използването 
            на Услугата след промените означава приемане на новите условия.
          </p>

          <h2>11. Приложимо право</h2>
          <p>
            Тези Условия се регулират от законите на Република България. Всички спорове ще се 
            решават в съдилищата на София, България.
          </p>

          <h2>12. Контакти</h2>
          <p>
            За въпроси относно тези Условия, свържете се с нас:
          </p>
          <ul>
            <li>Email: legal@bugbountyarsenal.com</li>
            <li>Email: support@bugbountyarsenal.com</li>
          </ul>

          <div className="bg-red-50 border-l-4 border-red-400 p-4 my-6">
            <p className="font-semibold text-red-800">🚨 ПРАВНО ПРЕДУПРЕЖДЕНИЕ:</p>
            <p className="text-red-700">
              Неразрешеното сканиране на компютърни системи е престъпление според Наказателния 
              кодекс на Република България (чл. 319а-319г). Нарушителите подлежат на 
              наказателно преследване и могат да бъдат осъдени на лишаване от свобода и глоби.
            </p>
          </div>

          <p className="text-sm text-gray-600 mt-8">
            Версия 1.0 | Последна актуализация: 31 Декември 2025
          </p>
        </div>
      </div>
    </div>
  );
};

export default Terms;
