'use strict';

// Helper function to check if value is a Date object
function isDate(value) {
  return value instanceof Date && !isNaN(value);
}

Date.prototype.yyyymmdd = function() {
    var yyyy = this.getFullYear().toString();
    var mm = (this.getMonth()+1).toString();
    var dd  = this.getDate().toString();
    return yyyy + '-' + (mm[1]?mm:'0'+mm[0]) + '-' + (dd[1]?dd:'0'+dd[0]);
};

Date.prototype.yyyymmddCompact = function() {
    var yyyy = this.getFullYear().toString();
    var mm = (this.getMonth()+1).toString();
    var dd  = this.getDate().toString();
    return yyyy + (mm[1]?mm:'0'+mm[0]) + (dd[1]?dd:'0'+dd[0]);
};

Date.prototype.ddSlashmm = function() {
    var mm = (this.getMonth()+1).toString();
    var dd  = this.getDate().toString();
    return (dd[1]?dd:'0'+dd[0]) + ' / ' + (mm[1]?mm:'0'+mm[0]);
};

Date.prototype.hhmm = function() {
    var hh = this.getHours().toString();
    var mm = this.getMinutes().toString();
    return (hh[1]?hh:'0'+hh[0]) + ':' + (mm[1]?mm:'0'+mm[0]);
};

Date.prototype.hhmmss = function() {
    var hh = this.getHours().toString();
    var mm = this.getMinutes().toString();
    var ss = this.getSeconds().toString();
    return (hh[1]?hh:'0'+hh[0]) + ':' + (mm[1]?mm:'0'+mm[0]) + ':' + (ss[1]?ss:'0'+ss[0]);
};

Date.prototype.yyyymmddSpacehhmmss = function() {
    var yyyymmdd = this.yyyymmdd();
    var hhmmss = this.hhmmss();
    return yyyymmdd + ' ' + hhmmss;
};

Date.prototype.dateTime = function() {
    var hh = this.getHours().toString();
    var mm = this.getMinutes().toString();
    return this.yyyymmdd() + ' ' + (hh[1]?hh:'0'+hh[0]) + ':' + (mm[1]?mm:'0'+mm[0]);
};

Date.prototype.yearsAgo = function(years) {
    this.setYear(this.getYear() + 1900 - years);
    return this;
};

Date.isMaxDate = function(date) {
    date = Date.newFull(date)
    return date && date.getFullYear() >= 9999;
};

Date.prototype.isMaxDate = function() {
    return Date.isMaxDate(this);
};

Date.prototype.getMillisecondsToday = function() {
    const startOfDay = this.clone();
    startOfDay.setHours(0, 0, 0, 0);
    return this.getTime() - startOfDay.getTime();
};

Date.rangeInside = function(startA, endA, startB, endB) {
    startA = startA.getTime();
    endA = endA.getTime();
    startB = startB.getTime();
    endB = endB.getTime();

    return (startA <= endB) && (endA >= startB) && (endA <= endB) && (startA >= startB);
};

Date.prototype.withinRange = function(a, b) {
    var t = this.yyyymmdd();
    if (isDate(a)) {
        a = a.yyyymmdd();
    }
    if (isDate(b)) {
        b = b.yyyymmdd();
    }
    return t >= a && t <= b;
};

Date.dateEquals = function(date1, date2) {
    if (!date1 || !date2) {
        return date1 == date2;
    }
    if (isDate(date1)) {
        date1 = date1.yyyymmdd();
    }
    if (isDate(date2)) {
        date2 = date2.yyyymmdd();
    }
    return date1 == date2;
};

Date.dateEqualsObjects = function(date1, date2) {
    if (!date1 || !date2) {
        return date1 == date2;
    }
    return date1.getDate() == date2.getDate() && date1.getMonth() == date2.getMonth() && date1.getFullYear() == date2.getFullYear();
};

Date.timeEquals = function(time1, time2) {
    if (!time1 || !time2) {
        return time1 == time2;
    }
    if (isDate(time1)) {
        time1 = time1.hhmm();
    }
    if (isDate(time2)) {
        time2 = time2.hhmm();
    }
    return time1 == time2;
};

Date.newFull = function(dateString) {
    if (!dateString) {
        return dateString;
    }
    if (isDate(dateString)) {
        return dateString.clone();
    }
    if (dateString.length == 8) {
        dateString = dateString.substring(0, 4) + '-' + dateString.substring(4, 6) + '-' + dateString.substring(6, 8);
    }

    var parts = dateString.split(' ');
    var datePart = parts[0];
    var d = datePart.split('-');
    var year = d[0];
    var month = d[1] - 1;
    var day = d[2];
    var hour = 0;
    var minute = 0;
    var second = 0;
    if (parts.length > 1) {
        var timePart = parts[1];
        var t = timePart.split(':');
        hour = t[0];
        if (t.length > 1) {
            minute = t[1];
        }
        if (t.length > 2) {
            second = t[2];
        }
    }
    return new Date(year, month, day, hour, minute, second, 0);
};

Date.newFromCompact = function(dateString) {
    if (isDate(dateString)) {
        return dateString;
    }

    var year = dateString.substring(0, 4);
    var month = dateString.substring(4, 6) - 1;
    var day = dateString.substring(6, 8);
    var hour = dateString.substring(8, 10);
    var minute = dateString.substring(10, 12);
    var second = dateString.substring(12, 14);
    return new Date(year, month, day, hour, minute, second, 0);
};

Date.newTime = function(dateString) {
    if (isDate(dateString)) {
        return dateString;
    }
    var d = new Date();
    var t = dateString.split(':');
    var hour = t[0];
    var minute = 0;
    var second = 0;
    if (t.length > 1) {
        minute = t[1];
    }
    if (t.length > 2) {
        second = t[2];
    }

    d.setHours(hour, minute, second);

    return d;
};

Date.prototype.clone = function() {
    return new Date(this.getTime());
};

Date.today = function() {
    return new Date().clearTime();
};

Date.tomorrow = function() {
    return new Date().addDays(1).clearTime();
};

Date.prototype.daysInMonth = function() {
    return new Date(this.getFullYear(), this.getMonth() + 1, 0).getDate();
};

Date.prototype.isFutureDate = function(inclusive) {
    var d = this.clone().clearTime();
    return d > Date.today() || (inclusive && d.isToday());
};

Date.prototype.isPastDate = function(inclusive) {
    var d = this.clone().clearTime();
    return d < Date.today() || (inclusive && d.isToday());
};

Date.prototype.isFuture = function() {
    return this > new Date();
};

Date.prototype.isToday = function() {
    return Date.dateEquals(this, Date.today());
};

Date.prototype.isTomorrow = function() {
    return Date.dateEquals(this, Date.tomorrow());
};

Date.monday = function() {
    var d = new Date();
    var day = d.getDay(),
        diff = d.getDate() - day + (day == 0 ? -6:1);
    d = new Date(d.setDate(diff));
    return d.clearTime();
};

Date.prototype.monday = function() {
    var d = this.clone();
    var day = d.getDay(),
        diff = d.getDate() - day + (day == 0 ? -6:1);
    d = new Date(d.setDate(diff));
    return d.clearTime();
};

Date.prototype.getDateIntervalForWeek = function() {
    var m = this.clone().monday();
    var s = m.clone().addDays(6);
    return [m, s];
};

Date.prototype.addDays = function(days) {
    this.setDate(this.getDate() + days);
    return this;
};

Date.isLeapYear = function (year) {
    return (((year % 4 === 0) && (year % 100 !== 0)) || (year % 400 === 0));
};

Date.getDaysInMonth = function (year, month) {
    return [31, (Date.isLeapYear(year) ? 29 : 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month];
};

Date.prototype.isLeapYear = function () {
    return Date.isLeapYear(this.getFullYear());
};

Date.prototype.getDaysInMonth = function () {
    return Date.getDaysInMonth(this.getFullYear(), this.getMonth());
};

Date.prototype.addMonths = function (value) {
    var n = this.getDate();
    this.setDate(1);
    this.setMonth(this.getMonth() + value);
    this.setDate(Math.min(n, this.getDaysInMonth()));
    return this;
};

Date.prototype.addMinutes = function(minutes) {
    this.setTime(this.getTime() + minutes*60000);
    return this;
};

Date.prototype.clearTime = function() {
    this.setHours(0,0,0,0);
    return this;
};

Date.prototype.isThisMonth = function() {
    var now = new Date();
    return this.getFullYear() == now.getFullYear() && this.getMonth() == now.getMonth();
};

Date.firstDayLastMonth = function() {
    var date = new Date();
    return new Date(date.getFullYear(), date.getMonth() - 1, 1);
};

Date.lastDayLastMonth = function() {
    var date = new Date();
    return new Date(date.getFullYear(), date.getMonth(), 0);
};

Date.firstDayThisMonth = function() {
    var date = new Date();
    return new Date(date.getFullYear(), date.getMonth(), 1);
};

Date.lastDayThisMonth = function() {
    var date = new Date();
    return new Date(date.getFullYear(), date.getMonth() + 1, 0);
};

Date.firstDayNextMonth = function() {
    var date = new Date();
    return new Date(date.getFullYear(), date.getMonth() + 1, 1);
};

Date.prototype.getWeekNumber = function() {
    var date = new Date(this.getTime());
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() + 3 - (date.getDay() + 6) % 7);
    var week1 = new Date(date.getFullYear(), 0, 4);
    return 1 + Math.round(((date.getTime() - week1.getTime()) / 86400000
                          - 3 + (week1.getDay() + 6) % 7) / 7);
};

Date.prototype.getMonthName = function() {
    return ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"][this.getMonth()];
};

Date.prototype.getMonthNameShort = function() {
    return ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][this.getMonth()];
};

Date.prototype.nextMonth = function() {
    return new Date(this.getFullYear(), this.getMonth() + 1, 1);
};

Date.prototype.lastMonth = function() {
    return new Date(this.getFullYear(), this.getMonth() - 1, 1);
};

Date.prototype.firstDayThisMonth = function() {
    return new Date(this.getFullYear(), this.getMonth(), 1);
};

Date.prototype.lastDayThisMonth = function() {
    return new Date(this.getFullYear(), this.getMonth() + 1, 0);
};

Date.prototype.daysUntil = function(date) {
    var oneDay = 24*60*60*1000;
    var diffDays = Math.floor((date.getTime() - this.getTime())/(oneDay));
    return diffDays;
};

Date.prototype.isSameDateAs = function(date) {
    return this.getFullYear() === date.getFullYear() &&
        this.getMonth() === date.getMonth() &&
        this.getDate() === date.getDate();
};

Date.prototype.isMidnight = function() {
    return this.getHours() == 0 && this.getMinutes() == 0 && this.getSeconds() == 0;
};

Date.prototype.daysFromToday = function() {
    return Date.today().daysUntil(this);
};

Date.prototype.getWeekDayString = function() {
    return ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][this.getDay()];
};

Date.prototype.getNextWeekDayOfType = function(weekDay) {
    var d = this.clone();
    return new Date(d.setDate(d.getDate() + (weekDay + 7 - d.getDay()) % 7)).clearTime();
};

Date.getAge = function(dateString) {
    var today = new Date();
    var birthDate = Date.newFull(dateString);
    var age = today.getFullYear() - birthDate.getFullYear();
    var m = today.getMonth() - birthDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
        age--;
    }
    return age;
}
