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
