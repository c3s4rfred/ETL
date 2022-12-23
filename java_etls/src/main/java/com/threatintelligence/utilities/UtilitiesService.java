package com.threatintelligence.utilities;

import java.time.*;
import java.time.format.DateTimeFormatter;

import com.threatintelligence.enums.EnvironmentsEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.threatintelligence.config.EnvironmentConfig;
import com.threatintelligence.enums.FeedTypeEnum;
import com.threatintelligence.enums.MonthEnum;

public class UtilitiesService {

    private static final Logger log = LoggerFactory.getLogger(UtilitiesService.class);
    private static final String CLASSNAME = "UtilitiesService";

    // Method to check if the Environment variables are well-defined
    public static boolean isEnvironmentOk() {
        if (
                EnvironmentConfig.FEED_URL == null ||
                        EnvironmentConfig.FEED_URL.compareTo("") == 0 ||
                        EnvironmentConfig.TW_API_URL == null ||
                        EnvironmentConfig.TW_API_URL.compareTo("") == 0 ||
                        EnvironmentConfig.FEED_FORMAT == null ||
                        EnvironmentConfig.FEED_FORMAT.compareTo("") == 0 ||
                        ((EnvironmentConfig.TW_AUTHENTICATION == null ||
                                EnvironmentConfig.TW_AUTHENTICATION.compareTo("") == 0) &&
                                (EnvironmentConfig.TW_API_KEY == null ||
                                        EnvironmentConfig.TW_API_KEY.compareTo("") == 0 ||
                                        EnvironmentConfig.TW_API_SECRET == null ||
                                        EnvironmentConfig.TW_API_SECRET.compareTo("") == 0)) ||
                        (EnvironmentConfig.THREAD_POOL_SIZE < 1) ||
                        (EnvironmentConfig.FEED_FORMAT.compareTo(FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue()) == 0 &&
                                (EnvironmentConfig.GITHUB_BRANCH_NAME == null || EnvironmentConfig.GITHUB_BRANCH_NAME.compareTo("") == 0))
        ) {
            log.error(
                    "\n *********** Check your environment configuration, some variables are not configured correctly ***********" +
                            "\n * " +
                            EnvironmentsEnum.FEED_FORMAT +
                            " is required, has to be defined and can't be empty" +
                            "\n * " +
                            EnvironmentsEnum.FEED_URL +
                            " is required, has to be defined and can't be empty" +
                            "\n * " +
                            EnvironmentsEnum.GITHUB_BRANCH_NAME +
                            " is required for " + FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue() + " feed format, has to be defined and can't be empty" +
                            "\n * " +
                            EnvironmentsEnum.THREAD_POOL_SIZE +
                            " must be greater than 0" +
                            "\n * " +
                            EnvironmentsEnum.TW_API_URL +
                            " is required, has to be defined and can't be empty" +
                            "\n * " +
                            EnvironmentsEnum.TW_AUTHENTICATION +
                            " is required if you don't define " + EnvironmentsEnum.TW_API_KEY + " and " + EnvironmentsEnum.TW_API_SECRET +
                            "\n * " +
                            EnvironmentsEnum.TW_API_KEY +
                            " is required if you don't define " + EnvironmentsEnum.TW_AUTHENTICATION +
                            "\n * " +
                            EnvironmentsEnum.TW_API_SECRET +
                            " is required if you don't define " + EnvironmentsEnum.TW_AUTHENTICATION +
                            "\n *********************************************************************************************************"
            );
            return false;
        }
        if (EnvironmentConfig.LINK_PATTERN.compareTo("") == 0 && isLinkPatternRequiredForFeedFormat()){
            log.warn(
                    "The variable " +
                            EnvironmentsEnum.LINK_PATTERN +
                            "is not defined correctly or have an empty value, if it is used in the process, will generate wrong values"
            );
        }
        log.info(
                "\n ********************************************** ENVIRONMENT **********************************************" +
                        "\n * " +
                        EnvironmentsEnum.FEED_FORMAT +
                        " = " +
                        EnvironmentConfig.FEED_FORMAT +
                        "\n * " +
                        EnvironmentsEnum.FEED_URL +
                        " = " +
                        EnvironmentConfig.FEED_URL +
                        "\n * " +
                        EnvironmentsEnum.GITHUB_BRANCH_NAME +
                        " = " +
                        EnvironmentConfig.GITHUB_BRANCH_NAME +
                        "\n * " +
                        EnvironmentsEnum.LINK_PATTERN +
                        " = " +
                        EnvironmentConfig.LINK_PATTERN +
                        "\n * " +
                        EnvironmentsEnum.THREAD_POOL_SIZE +
                        " = " +
                        EnvironmentConfig.THREAD_POOL_SIZE +
                        "\n * " +
                        EnvironmentsEnum.TW_API_URL +
                        " = " +
                        EnvironmentConfig.TW_API_URL +
                        "\n * " +
                        EnvironmentsEnum.TW_API_VERSION +
                        " = " +
                        EnvironmentConfig.TW_API_VERSION +
                        "\n * " +
                        EnvironmentsEnum.TW_AUTHENTICATION +
                        " = " +
                        EnvironmentConfig.TW_AUTHENTICATION +
                        "\n * " +
                        EnvironmentsEnum.TW_API_KEY +
                        " = " +
                        EnvironmentConfig.TW_API_KEY +
                        "\n * " +
                        EnvironmentsEnum.TW_API_SECRET +
                        " = " +
                        EnvironmentConfig.TW_API_SECRET +
                        "\n * " +
                        EnvironmentsEnum.TW_API_ENTITY_BASE_TYPE +
                        " = " +
                        EnvironmentConfig.TW_API_ENTITY_BASE_TYPE +
                        "\n *********************************************************************************************************"
        );
        return true;
    }

    // Method format date strings to RFC 3339 Nano
    public static String getEpochFormatDate(String dateString) {
        try {
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ");
            String localTime = "00:00:00";
            String datePattern = "";
            // Short version of Month name format, like "2 Feb 2022"
            /* Supported variants:
               - 2 Feb 2022; 02 Feb 2022; Feb 2, 2022; Feb 02, 2022; 2022 Feb 2; 2022 Feb 02
            * */
            if (dateString.matches("(\\d)(\\s)(\\w{3})(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[1];
                datePattern = "d M yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\d{2})(\\s)(\\w{3})(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[1];
                datePattern = "dd M yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\w{3})(\\s)(\\d),(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[0];
                datePattern = "M d, yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\w{3})(\\s)(\\d{2}),(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[0];
                datePattern = "M dd, yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\d{4})(\\s)(\\w{3})(\\s)(\\d)")) {
                String month = dateString.split("\\s")[1];
                datePattern = "yyyy M d";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\d{4})(\\s)(\\w{3})(\\s)(\\d{2})")) {
                String month = dateString.split("\\s")[1];
                datePattern = "yyyy M dd";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } // Long version of Month name format, like "2 February 2022"
            /* Supported variants:
               - 2 February 2022; 02 February 2022; February 2, 2022; February 02, 2022; 2022 February 2; 2022 February 02
            * */
            else if (dateString.matches("(\\d)(\\s)(\\w+)(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[1];
                datePattern = "d M yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\d{2})(\\s)(\\w+)(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[1];
                datePattern = "dd M yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\w+)(\\s)(\\d),(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[0];
                datePattern = "M d, yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\w+)(\\s)(\\d{2}),(\\s)(\\d{4})")) {
                String month = dateString.split("\\s")[0];
                datePattern = "M dd, yyyy";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\d{4})(\\s)(\\w+)(\\s)(\\d)")) {
                String month = dateString.split("\\s")[1];
                datePattern = "yyyy M d";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            } else if (dateString.matches("(\\d{4})(\\s)(\\w+)(\\s)(\\d{2})")) {
                String month = dateString.split("\\s")[1];
                datePattern = "yyyy M dd";
                dateString = dateString.replace(month, MonthEnum.getMonth(month, true));
            }/* Supported variants:
             *  - 01/01/2022; 01-01-2022; 2022/01/01; 2022-01-01
             */ else if (dateString.matches("(\\d{2})/(\\d{1,2})/(\\d{4})")) {
                datePattern = "dd/MM/yyyy";
            } else if (dateString.matches("(\\d{2})-(\\d{1,2})-(\\d{4})")) {
                datePattern = "dd-MM-yyyy";
            } else if (dateString.matches("(\\d{4})/(\\d{1,2})/(\\d{2})")) {
                datePattern = "yyyy/MM/dd";
            } else if (dateString.matches("(\\d{4})-(\\d{1,2})-(\\d{2})")) {
                datePattern = "yyyy-MM-dd";
            }/* Supported variants:
             *  - 1/1/2022; 1-1-2022; 2022/1/1; 2022-1-1
             */ else if (dateString.matches("(\\d)/(\\d)/(\\d{4})")) {
                datePattern = "d/M/yyyy";
            } else if (dateString.matches("(\\d)-(\\d)-(\\d{4})")) {
                datePattern = "d-M-yyyy";
            } else if (dateString.matches("(\\d{4})/(\\d)/(\\d)")) {
                datePattern = "yyyy/M/d";
            } else if (dateString.matches("(\\d{4})-(\\d)-(\\d)")) {
                datePattern = "yyyy-M-d";
            }/* Supported variants:
             *  - 2018-01-01T00:00:00; 2018-01-01 00:00:00
             */ else if (dateString.matches("(\\d{4})-(\\d{1,2})-(\\d{1,2})T(\\d{2}):(\\d{2}):(\\d{2})")) {
                datePattern = "yyyy-MM-dd";
                localTime = dateString.split("T")[1];
                dateString = dateString.split("T")[0];
            } else if (dateString.matches("(\\d{4})-(\\d{1,2})-(\\d{1,2})\\s(\\d{2}):(\\d{2}):(\\d{2})")) {
                datePattern = "yyyy-MM-dd";
                localTime = dateString.split("\\s")[1];
                dateString = dateString.split("\\s")[0];
            }
            LocalDateTime ldt = LocalDateTime.of(
                    LocalDate.parse(dateString, DateTimeFormatter.ofPattern(datePattern)),
                    LocalTime.parse(localTime)
            );
            ZonedDateTime zdt = ZonedDateTime.of(ldt, ZoneId.systemDefault());

            String epochDateTimeString = dtf.format(zdt);
            return epochDateTimeString.replaceFirst("(\\d\\.\\d+)(-|\\+)(\\d{4})", "$1Z");
        } catch (Exception ex) {
            return dateString;
        }
    }

    // Method used to know if link_pattern is required for EnvironmentConfig.FEED_FORMAT feed format
    public static boolean isLinkPatternRequiredForFeedFormat() {

        if (FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                FeedTypeEnum.TYPE_RFXN_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
            return false;
        }
        return true;
    }
}
