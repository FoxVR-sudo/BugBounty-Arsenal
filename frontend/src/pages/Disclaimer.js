import React from 'react';
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiAlertTriangle } from 'react-icons/fi';

const Disclaimer = () => {
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
            <FiAlertTriangle className="text-yellow-500 text-3xl" />
            <h1 className="text-3xl font-bold text-white">Legal Disclaimer</h1>
          </div>
          <p className="text-gray-400 mt-2">Last Updated: December 31, 2025</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="bg-white rounded-lg shadow-xl p-8 prose prose-lg max-w-none">
          
          <div className="bg-red-50 border-l-4 border-red-500 p-6 my-6">
            <h2 className="text-red-800 mt-0">⚠️ READ THIS CAREFULLY</h2>
            <p className="text-red-700 font-semibold">
              Unauthorized vulnerability scanning is ILLEGAL and can result in criminal prosecution, 
              imprisonment, and substantial fines. By using this tool, you accept FULL responsibility 
              for your actions.
            </p>
          </div>

          <h2>1. Educational Purpose Only</h2>
          <p>
            BugBounty Arsenal is intended EXCLUSIVELY for:
          </p>
          <ul>
            <li>Security researchers conducting authorized testing</li>
            <li>Ethical hackers with proper permissions</li>
            <li>Penetration testers under contract</li>
            <li>Students learning in controlled lab environments</li>
            <li>Bug bounty program participants</li>
          </ul>

          <h2>2. Legal Prohibition</h2>
          <div className="bg-red-50 border border-red-200 rounded p-4 my-4">
            <h3 className="text-red-800 mt-0">🚨 CRIMINAL OFFENSE</h3>
            <p className="text-red-700">
              Scanning systems without explicit authorization is ILLEGAL under:
            </p>
            <ul className="text-red-700">
              <li><strong>Bulgarian Criminal Code:</strong> Articles 319a-319d (Computer Crimes)</li>
              <li><strong>GDPR:</strong> Unauthorized data processing violations</li>
              <li><strong>US Computer Fraud and Abuse Act (CFAA)</strong></li>
              <li><strong>UK Computer Misuse Act 1990</strong></li>
              <li>Similar laws in virtually all countries worldwide</li>
            </ul>
            <p className="text-red-700 font-semibold mt-4">
              <strong>Penalties may include:</strong>
            </p>
            <ul className="text-red-700">
              <li>Prison sentences up to 6 years or more</li>
              <li>Fines up to 10,000 BGN or more</li>
              <li>Civil lawsuits for damages</li>
              <li>Permanent criminal record</li>
            </ul>
          </div>

          <h2>3. User Responsibility</h2>
          <p>
            <strong>YOU ARE SOLELY RESPONSIBLE FOR:</strong>
          </p>
          <ul>
            <li>Obtaining written authorization before scanning ANY system</li>
            <li>Complying with all applicable laws and regulations</li>
            <li>Understanding and following bug bounty program rules</li>
            <li>Any and all consequences of your scanning activities</li>
            <li>Damages to systems or data</li>
            <li>Legal fees and penalties</li>
          </ul>

          <h2>4. No Warranties</h2>
          <p>
            BugBounty Arsenal is provided "AS IS" without warranties of any kind:
          </p>
          <ul>
            <li><strong>No accuracy guarantee:</strong> Results may include false positives or false negatives</li>
            <li><strong>No completeness guarantee:</strong> Not all vulnerabilities may be detected</li>
            <li><strong>No uptime guarantee:</strong> Service may be unavailable</li>
            <li><strong>No fitness guarantee:</strong> Tool may not meet your specific needs</li>
          </ul>

          <h2>5. Limitation of Liability</h2>
          <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 my-4">
            <p className="font-semibold text-yellow-800">
              BugBounty Arsenal and its operators SHALL NOT BE LIABLE for:
            </p>
            <ul className="text-yellow-700">
              <li>Illegal use of the Service by users</li>
              <li>Damages to scanned systems or data</li>
              <li>Financial losses resulting from scans</li>
              <li>Reputational damage</li>
              <li>Legal consequences or prosecution</li>
              <li>False positives causing unnecessary work</li>
              <li>Missed vulnerabilities leading to breaches</li>
              <li>Third-party claims or lawsuits</li>
            </ul>
          </div>

          <h2>6. Indemnification</h2>
          <p>
            You agree to INDEMNIFY, DEFEND, and HOLD HARMLESS BugBounty Arsenal, its owners, operators, 
            and affiliates from any claims, damages, losses, liabilities, and expenses (including legal fees) 
            arising from your use of the Service.
          </p>

          <h2>7. Professional Advice Disclaimer</h2>
          <p>
            The Service does not provide legal, professional, or expert advice. Results should be verified 
            by qualified security professionals. Do not rely solely on automated scan results.
          </p>

          <h2>8. Responsible Disclosure</h2>
          <p>
            If you discover vulnerabilities using this tool:
          </p>
          <ul>
            <li><strong>DO NOT</strong> publicly disclose without permission</li>
            <li><strong>DO</strong> contact the system owner privately</li>
            <li><strong>DO</strong> follow responsible disclosure guidelines</li>
            <li><strong>DO</strong> allow reasonable time for fixes (typically 90 days)</li>
            <li><strong>DO</strong> respect bug bounty program policies</li>
          </ul>

          <h2>9. Prohibited Targets</h2>
          <div className="bg-red-50 border border-red-200 rounded p-4 my-4">
            <h3 className="text-red-800 mt-0">🚫 NEVER SCAN:</h3>
            <ul className="text-red-700">
              <li>Government or military systems (without explicit authorization)</li>
              <li>Critical infrastructure (power, water, healthcare, etc.)</li>
              <li>Financial institutions without permission</li>
              <li>Healthcare systems containing patient data</li>
              <li>Educational institutions without authorization</li>
              <li>Any system with explicit "no scanning" policies</li>
              <li>Third-party systems during security audits (without scope approval)</li>
            </ul>
          </div>

          <h2>10. Service Modifications</h2>
          <p>
            We reserve the right to modify, suspend, or discontinue the Service at any time without notice. 
            We are not liable for any modifications or interruptions.
          </p>

          <h2>11. Jurisdiction</h2>
          <p>
            This Disclaimer is governed by Bulgarian law. Any legal disputes shall be resolved exclusively 
            in the courts of Sofia, Bulgaria.
          </p>

          <h2>12. Severability</h2>
          <p>
            If any provision of this Disclaimer is found invalid or unenforceable, the remaining provisions 
            shall continue in full force and effect.
          </p>

          <div className="bg-gray-900 text-white rounded-lg p-6 my-8">
            <h3 className="text-yellow-400 flex items-center gap-2">
              <FiAlertTriangle />
              FINAL WARNING
            </h3>
            <p className="mt-4">
              By using BugBounty Arsenal, you acknowledge that you have read, understood, and agreed to this 
              Disclaimer. You confirm that you will ONLY scan systems you own or have explicit written 
              authorization to test.
            </p>
            <p className="mt-4 font-semibold text-red-400">
              IF YOU DO NOT AGREE OR DO NOT HAVE PROPER AUTHORIZATION, DO NOT USE THIS SERVICE.
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

export default Disclaimer;
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiAlertTriangle } from 'react-icons/fi';

const Disclaimer = () => {
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
            <FiAlertTriangle className="text-red-500 text-3xl" />
            <h1 className="text-3xl font-bold text-white">Отказ от отговорност</h1>
          </div>
          <p className="text-gray-400 mt-2">Последна актуализация: 31 Декември 2025</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="bg-white rounded-lg shadow-xl p-8 prose prose-lg max-w-none">
          
          <div className="bg-red-50 border-l-4 border-red-500 p-6 my-6">
            <h2 className="text-red-800 mt-0">🚨 ВАЖНО ПРАВНО ПРЕДУПРЕЖДЕНИЕ</h2>
            <p className="text-red-700 font-semibold">
              ПРОЧЕТЕТЕ ВНИМАТЕЛНО ПРЕДИ ИЗПОЛЗВАНЕ НА BUGBOUNTY ARSENAL
            </p>
          </div>

          <h2>1. Образователна цел</h2>
          <p>
            BugBounty Arsenal е създаден единствено с ОБРАЗОВАТЕЛНА цел и за ЛЕГАЛНИ 
            penetration testing дейности. Инструментът е предназначен за:
          </p>
          <ul>
            <li>Security researchers и ethical hackers</li>
            <li>Penetration testers с валидно разрешение</li>
            <li>IT специалисти, тестващи собствени системи</li>
            <li>Студенти в контролирана образователна среда</li>
            <li>Участници в легални bug bounty програми</li>
          </ul>

          <h2>2. Забрана за незаконно използване</h2>
          <p>
            Използването на BugBounty Arsenal за сканиране на системи БЕЗ ИЗРИЧНО ПИСМЕНО 
            РАЗРЕШЕНИЕ е НЕЗАКОННО и представлява престъпление според:
          </p>
          <ul>
            <li>Наказателен кодекс на РБ (чл. 319а-319г) - Компютърни престъпления</li>
            <li>GDPR - Неразрешен достъп до лични данни</li>
            <li>Computer Fraud and Abuse Act (USA)</li>
            <li>Computer Misuse Act (UK)</li>
          </ul>

          <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 my-4">
            <p className="font-semibold text-yellow-800">⚠️ Наказателна отговорност:</p>
            <ul className="text-yellow-700">
              <li>Лишаване от свобода до 6 години</li>
              <li>Глоби до 10,000 лв.</li>
              <li>Граждански искове за обезщетения</li>
              <li>Криминално досие</li>
            </ul>
          </div>

          <h2>3. Пълна отговорност на потребителя</h2>
          <p>
            Използвайки BugBounty Arsenal, ВИЕ НОСИТЕ ПЪЛНА ОТГОВОРНОСТ за:
          </p>
          <ul>
            <li>Получаване на необходимите разрешения преди сканиране</li>
            <li>Спазване на законите на вашата юрисдикция</li>
            <li>Спазване на Terms of Service на тестваните системи</li>
            <li>Щети, причинени на тествани системи</li>
            <li>Правни последствия от вашите действия</li>
            <li>Етично поведение и responsible disclosure</li>
          </ul>

          <h2>4. Ограничение на гаранциите</h2>
          <p>
            BugBounty Arsenal се предоставя "AS IS" БЕЗ НИКАКВИ ГАРАНЦИИ:
          </p>
          <ul>
            <li>НЕ гарантираме точност на резултатите (възможни false positives/negatives)</li>
            <li>НЕ гарантираме непрекъснат или безпроблемен достъп до услугата</li>
            <li>НЕ гарантираме откриване на всички уязвимости</li>
            <li>НЕ гарантираме съвместимост със всички системи</li>
            <li>НЕ гарантираме защита срещу countermeasures (WAF, IPS, etc.)</li>
          </ul>

          <h2>5. Ограничение на отговорността</h2>
          <p>
            BugBounty Arsenal и неговите разработчици, служители и партньори 
            НЕ НОСЯТ ОТГОВОРНОСТ за:
          </p>
          <ul>
            <li>Незаконни действия на потребителите</li>
            <li>Щети на тествани системи (downtime, data loss, corruption)</li>
            <li>Финансови загуби или пропуснати ползи</li>
            <li>Репутационни щети</li>
            <li>Правни разходи и съдебни искове</li>
            <li>Косвени, случайни или последващи щети</li>
            <li>Загуба на открити уязвимости поради technical issues</li>
          </ul>

          <h2>6. Индемнификация (Обезщетение)</h2>
          <p>
            Вие се съгласявате да ОБЕЗЩЕТИТЕ И ЗАЩИТИТЕ BugBounty Arsenal, неговите 
            разработчици и партньори от всички искове, загуби, щети, отговорности и 
            разходи (включително адвокатски хонорари), произтичащи от:
          </p>
          <ul>
            <li>Вашето използване или злоупотреба с услугата</li>
            <li>Нарушение на тези условия</li>
            <li>Нарушение на закони или права на трети лица</li>
            <li>Незаконно сканиране на системи</li>
          </ul>

          <h2>7. Технически рискове</h2>
          <p>Използването на security scanning tools носи рискове:</p>
          <ul>
            <li><strong>Detection:</strong> Вашите IP адреси могат да бъдат блокирани</li>
            <li><strong>Legal action:</strong> Собствениците на системи могат да предприемат правни действия</li>
            <li><strong>Collateral damage:</strong> Aggressive scans могат да причинят DoS</li>
            <li><strong>Data exposure:</strong> Случайно disclosure на sensitive data</li>
          </ul>

          <h2>8. Responsible Disclosure</h2>
          <p>
            При откриване на уязвимости, следвайте принципите на responsible disclosure:
          </p>
          <ul>
            <li>НЕ публикувайте уязвимости публично без разрешение</li>
            <li>Свържете се ПЪРВО с owner-а на системата</li>
            <li>Дайте разумен срок за fixing (обикновено 90 дни)</li>
            <li>Документирайте комуникацията</li>
            <li>Следвайте bug bounty program rules, ако има такива</li>
          </ul>

          <h2>9. Забранени цели</h2>
          <div className="bg-red-50 border border-red-200 p-4 my-4">
            <p className="font-semibold text-red-800">Строго забранено е сканиране на:</p>
            <ul className="text-red-700">
              <li>Правителствени и военни системи (без официално разрешение)</li>
              <li>Критична инфраструктура (power grids, water, transport)</li>
              <li>Финансови институции (банки, payment processors)</li>
              <li>Healthcare системи (болници, medical devices)</li>
              <li>Образователни институции (без IT отдел approval)</li>
              <li>Системи с explicit "No scanning" policy</li>
            </ul>
          </div>

          <h2>10. Препоръки за безопасност</h2>
          <p>За минимизиране на рисковете:</p>
          <ul>
            <li>ВИНАГИ получавайте писмено разрешение</li>
            <li>Използвайте rate limiting и respectful scanning</li>
            <li>Тествайте в non-production environment когато е възможно</li>
            <li>Имайте backup plan при проблеми</li>
            <li>Документирайте всички действия</li>
            <li>Използвайте VPN/proxy за допълнителна защита</li>
            <li>Проверете дали има bug bounty program първо</li>
          </ul>

          <h2>11. Приемане на риска</h2>
          <p>
            Използвайки BugBounty Arsenal, вие потвърждавате че:
          </p>
          <ul>
            <li>Сте прочели и разбрали този Отказ от отговорност</li>
            <li>Сте наясно с правните рискове</li>
            <li>Ще използвате инструмента САМО легално</li>
            <li>Приемате ПЪЛНАТА отговорност за вашите действия</li>
            <li>Освобождавате BugBounty Arsenal от всякаква отговорност</li>
          </ul>

          <div className="bg-gray-100 border-l-4 border-gray-400 p-4 my-6">
            <p className="font-semibold">📞 Съмнения? Свържете се с нас:</p>
            <ul>
              <li>Email: legal@bugbountyarsenal.com</li>
              <li>Support: support@bugbountyarsenal.com</li>
            </ul>
            <p className="text-sm mt-2">
              При съмнения относно легалността на сканиране, 
              консултирайте се с адвокат преди да продължите.
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

export default Disclaimer;
